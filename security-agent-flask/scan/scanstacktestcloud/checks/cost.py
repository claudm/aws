"""Checks de otimização de custo. Todas as estimativas são aproximações
mensais em USD, usadas para ordenar o que atacar primeiro."""

from __future__ import annotations

import datetime as dt
from typing import Any, Dict, Iterable, List, Optional

from .. import pricing
from ..context import ScanContext, days_since, env_exposure, tags_to_dict, utcnow
from ..models import Pillar, Severity
from ..registry import check
from .compute import load_balancers
from .ec2 import instances, volumes

LOOKBACK_DAYS = 14
SNAPSHOT_STALE_DAYS = 180
CPU_IDLE_THRESHOLD = 5.0


def _chunks(seq: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def metric_series(
    ctx: ScanContext,
    queries: List[Dict[str, Any]],
    days: int = LOOKBACK_DAYS,
    period: int = 86400,
) -> Dict[str, List[float]]:
    """Coleta métricas em lote via GetMetricData. `queries` usa chaves:
    key, namespace, metric, dimensions (dict), stat."""
    if not queries:
        return {}
    cw = ctx.client("cloudwatch")
    end = utcnow()
    start = end - dt.timedelta(days=days)
    out: Dict[str, List[float]] = {}
    for chunk in _chunks(queries, 100):
        ids = {f"m{i}": q["key"] for i, q in enumerate(chunk)}
        mdq = [
            {
                "Id": mid,
                "MetricStat": {
                    "Metric": {
                        "Namespace": q["namespace"],
                        "MetricName": q["metric"],
                        "Dimensions": [
                            {"Name": k, "Value": v} for k, v in q["dimensions"].items()
                        ],
                    },
                    "Period": period,
                    "Stat": q.get("stat", "Average"),
                },
                "ReturnData": True,
            }
            for mid, q in zip(ids, chunk)
        ]
        resp = cw.get_metric_data(MetricDataQueries=mdq, StartTime=start, EndTime=end)
        for res in resp.get("MetricDataResults", []):
            out[ids[res["Id"]]] = res.get("Values", [])
    return out


@check(
    "COST.EBS_UNATTACHED",
    "Volume EBS órfão",
    Pillar.COST,
    "ec2",
    well_architected="COST04-BP03",
    permissions=["ec2:DescribeVolumes"],
)
def unattached_volumes(ctx: ScanContext):
    for vol in volumes(ctx):
        if vol.get("State") != "available":
            continue
        cost = pricing.ebs_monthly(
            vol.get("VolumeType", "gp2"),
            vol.get("Size", 0),
            vol.get("Iops", 0),
            vol.get("Throughput", 0),
        )
        age = days_since(vol.get("CreateTime"))
        tags = tags_to_dict(vol.get("Tags"))
        yield ctx.finding(
            title=f"Volume {vol['VolumeId']} ({vol['Size']} GiB {vol.get('VolumeType')}) sem anexo",
            severity=Severity.MEDIUM if cost >= 10 else Severity.LOW,
            pillar=Pillar.COST,
            resource_id=vol["VolumeId"],
            resource_arn=ctx.arn("ec2", f"volume/{vol['VolumeId']}"),
            description=(
                f"O volume está no estado 'available' há algum tempo (criado há {age} dias) e "
                "continua sendo cobrado integralmente."
            ),
            remediation="Tire um snapshot final e delete o volume. Automatize com uma regra de lifecycle/tag.",
            evidence={"size_gb": vol.get("Size"), "type": vol.get("VolumeType"), "name": tags.get("Name")},
            monthly_waste_usd=cost,
            exposure=["empty_resource"],
        )


@check(
    "COST.GP2_VOLUMES",
    "Volumes gp2 migráveis para gp3",
    Pillar.COST,
    "ec2",
    well_architected="COST05-BP04",
    permissions=["ec2:DescribeVolumes"],
)
def gp2_volumes(ctx: ScanContext):
    targets = [v for v in volumes(ctx) if v.get("VolumeType") == "gp2"]
    if not targets:
        return
    total_gb = sum(v.get("Size", 0) for v in targets)
    saving = pricing.gp2_to_gp3_saving(total_gb)
    yield ctx.finding(
        title=f"{len(targets)} volume(s) gp2 ({total_gb} GiB) ainda não migrados para gp3",
        severity=Severity.LOW,
        pillar=Pillar.COST,
        resource_id=f"gp2-fleet:{ctx.region}",
        description=(
            "gp3 custa ~20% menos por GiB e entrega 3.000 IOPS / 125 MB/s de baseline sem "
            "depender do tamanho do volume."
        ),
        remediation=(
            "modify-volume --volume-type gp3 é online e sem downtime. Valide antes volumes "
            "grandes que dependem do burst de IOPS proporcional do gp2."
        ),
        evidence={"volume_ids": [v["VolumeId"] for v in targets][:50], "total_gib": total_gb},
        monthly_waste_usd=saving,
    )


@check(
    "COST.EIP_UNASSOCIATED",
    "Elastic IP ocioso",
    Pillar.COST,
    "ec2",
    well_architected="COST04-BP03",
    permissions=["ec2:DescribeAddresses"],
)
def idle_eips(ctx: ScanContext):
    resp = ctx.call("ec2", "describe_addresses")
    for addr in (resp or {}).get("Addresses", []):
        if addr.get("AssociationId"):
            continue
        yield ctx.finding(
            title=f"Elastic IP {addr.get('PublicIp')} não está associado",
            severity=Severity.LOW,
            pillar=Pillar.COST,
            resource_id=addr.get("AllocationId", addr.get("PublicIp", "")),
            resource_arn=ctx.arn("ec2", f"elastic-ip/{addr.get('AllocationId')}"),
            description="Endereços IPv4 públicos são cobrados por hora mesmo sem uso.",
            remediation="Release o endereço, ou associe-o se ele estiver reservado para failover.",
            monthly_waste_usd=round(pricing.EIP_IDLE_HOUR * pricing.HOURS_PER_MONTH, 2),
            exposure=["empty_resource"],
        )


@check(
    "COST.STOPPED_INSTANCES",
    "Instância parada há muito tempo",
    Pillar.COST,
    "ec2",
    well_architected="COST04-BP03",
    permissions=["ec2:DescribeInstances", "ec2:DescribeVolumes"],
)
def stopped_instances(ctx: ScanContext):
    vol_by_id = {v["VolumeId"]: v for v in volumes(ctx)}
    for inst in instances(ctx):
        if inst.get("State", {}).get("Name") != "stopped":
            continue
        attached = [
            m["Ebs"]["VolumeId"]
            for m in inst.get("BlockDeviceMappings", [])
            if m.get("Ebs", {}).get("VolumeId")
        ]
        cost = 0.0
        gib = 0
        for vid in attached:
            v = vol_by_id.get(vid)
            if not v:
                continue
            gib += v.get("Size", 0)
            cost += pricing.ebs_monthly(v.get("VolumeType", "gp2"), v.get("Size", 0))
        tags = tags_to_dict(inst.get("Tags"))
        yield ctx.finding(
            title=f"Instância {inst['InstanceId']} parada, mantendo {gib} GiB de EBS",
            severity=Severity.LOW,
            pillar=Pillar.COST,
            resource_id=inst["InstanceId"],
            resource_arn=ctx.arn("ec2", f"instance/{inst['InstanceId']}"),
            description=(
                "Instâncias paradas não custam compute, mas os volumes e IPs continuam faturando. "
                "Frequentemente são restos de testes."
            ),
            remediation="Crie uma AMI e termine a instância, ou documente a razão de mantê-la parada.",
            evidence={"name": tags.get("Name"), "type": inst.get("InstanceType"), "volumes": attached},
            monthly_waste_usd=round(cost, 2),
            exposure=env_exposure(tags) or ["empty_resource"],
        )


@check(
    "COST.EC2_UNDERUTILIZED",
    "Instância subutilizada",
    Pillar.COST,
    "ec2",
    well_architected="COST06-BP02",
    permissions=["ec2:DescribeInstances", "cloudwatch:GetMetricData"],
)
def underutilized(ctx: ScanContext):
    running = [i for i in instances(ctx) if i.get("State", {}).get("Name") == "running"]
    if not running:
        return
    series = metric_series(
        ctx,
        [
            {
                "key": i["InstanceId"],
                "namespace": "AWS/EC2",
                "metric": "CPUUtilization",
                "dimensions": {"InstanceId": i["InstanceId"]},
                "stat": "Average",
            }
            for i in running
        ],
    )
    peaks = metric_series(
        ctx,
        [
            {
                "key": i["InstanceId"],
                "namespace": "AWS/EC2",
                "metric": "CPUUtilization",
                "dimensions": {"InstanceId": i["InstanceId"]},
                "stat": "Maximum",
            }
            for i in running
        ],
    )
    for inst in running:
        values = series.get(inst["InstanceId"], [])
        if len(values) < 5:  # dados insuficientes para concluir
            continue
        avg = sum(values) / len(values)
        peak = max(peaks.get(inst["InstanceId"], [0]) or [0])
        if avg >= CPU_IDLE_THRESHOLD or peak >= 40:
            continue
        tags = tags_to_dict(inst.get("Tags"))
        monthly = pricing.ec2_monthly(ctx, inst.get("InstanceType", ""))
        yield ctx.finding(
            title=f"Instância {inst['InstanceId']} ({inst.get('InstanceType')}) com CPU média de {avg:.1f}%",
            severity=Severity.LOW,
            pillar=Pillar.COST,
            resource_id=inst["InstanceId"],
            resource_arn=ctx.arn("ec2", f"instance/{inst['InstanceId']}"),
            description=(
                f"Nos últimos {LOOKBACK_DAYS} dias a CPU ficou em {avg:.1f}% em média e "
                f"{peak:.1f}% no pico. Candidata a downsizing ou a família Graviton."
            ),
            remediation=(
                "Confirme se o gargalo não é memória ou I/O (o CloudWatch padrão não vê RAM). "
                "Depois reduza um tamanho na família ou migre para t4g/m7g."
            ),
            evidence={"avg_cpu": round(avg, 2), "max_cpu": round(peak, 2), "name": tags.get("Name")},
            monthly_waste_usd=round(monthly * 0.4, 2) if monthly else 0.0,
            exposure=env_exposure(tags),
        )


@check(
    "COST.STALE_SNAPSHOTS",
    "Snapshots antigos acumulados",
    Pillar.COST,
    "ec2",
    well_architected="COST04-BP02",
    permissions=["ec2:DescribeSnapshots"],
)
def stale_snapshots(ctx: ScanContext):
    snaps = ctx.cached(
        "ec2:snapshots",
        lambda: ctx.paginate("ec2", "describe_snapshots", "Snapshots", OwnerIds=["self"]),
    )
    stale = [s for s in snaps if (days_since(s.get("StartTime")) or 0) > SNAPSHOT_STALE_DAYS]
    if not stale:
        return
    total_gb = sum(s.get("VolumeSize", 0) for s in stale)
    yield ctx.finding(
        title=f"{len(stale)} snapshot(s) com mais de {SNAPSHOT_STALE_DAYS} dias ({total_gb} GiB de origem)",
        severity=Severity.LOW,
        pillar=Pillar.COST,
        resource_id=f"stale-snapshots:{ctx.region}",
        description=(
            "Snapshots manuais não expiram sozinhos. Em contas antigas eles costumam ser a "
            "maior linha silenciosa da fatura de EBS."
        ),
        remediation=(
            "Adote Data Lifecycle Manager com política de retenção, e revise snapshots manuais "
            "sem tag de owner antes de apagar."
        ),
        evidence={"oldest_days": max(days_since(s.get("StartTime")) or 0 for s in stale),
                  "snapshot_ids": [s["SnapshotId"] for s in stale][:50]},
        monthly_waste_usd=pricing.snapshot_monthly(total_gb),
    )


@check(
    "COST.IDLE_LOAD_BALANCER",
    "Load balancer sem targets saudáveis",
    Pillar.COST,
    "elbv2",
    well_architected="COST04-BP03",
    permissions=["elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth"],
)
def idle_load_balancers(ctx: ScanContext):
    for lb in load_balancers(ctx):
        tgs = ctx.paginate(
            "elbv2", "describe_target_groups", "TargetGroups", LoadBalancerArn=lb["LoadBalancerArn"]
        )
        healthy = 0
        for tg in tgs:
            resp = ctx.call(
                "elbv2", "describe_target_health", TargetGroupArn=tg["TargetGroupArn"]
            )
            healthy += sum(
                1
                for t in (resp or {}).get("TargetHealthDescriptions", [])
                if t.get("TargetHealth", {}).get("State") == "healthy"
            )
        if healthy:
            continue
        hourly = pricing.ALB_HOUR if lb.get("Type") == "application" else pricing.NLB_HOUR
        yield ctx.finding(
            title=f"Load balancer '{lb['LoadBalancerName']}' sem nenhum target saudável",
            severity=Severity.MEDIUM,
            pillar=Pillar.COST,
            resource_id=lb["LoadBalancerName"],
            resource_arn=lb["LoadBalancerArn"],
            description=(
                f"{len(tgs)} target group(s) e zero targets saudáveis. Ou o serviço foi "
                "desativado e o LB ficou, ou existe uma indisponibilidade em curso."
            ),
            remediation="Confirme se a aplicação foi descomissionada; em caso positivo, remova o LB e o Route 53 record.",
            evidence={"target_groups": len(tgs), "scheme": lb.get("Scheme"), "type": lb.get("Type")},
            monthly_waste_usd=round(hourly * pricing.HOURS_PER_MONTH, 2),
            exposure=["empty_resource"],
        )


@check(
    "COST.IDLE_NAT_GATEWAY",
    "NAT Gateway sem tráfego",
    Pillar.COST,
    "ec2",
    well_architected="COST04-BP03",
    permissions=["ec2:DescribeNatGateways", "cloudwatch:GetMetricData"],
)
def idle_nat(ctx: ScanContext):
    gws = [
        g
        for g in ctx.paginate("ec2", "describe_nat_gateways", "NatGateways")
        if g.get("State") == "available"
    ]
    if not gws:
        return
    series = metric_series(
        ctx,
        [
            {
                "key": g["NatGatewayId"],
                "namespace": "AWS/NATGateway",
                "metric": "BytesOutToDestination",
                "dimensions": {"NatGatewayId": g["NatGatewayId"]},
                "stat": "Sum",
            }
            for g in gws
        ],
    )
    for gw in gws:
        values = series.get(gw["NatGatewayId"], [])
        total = sum(values)
        if len(values) < 5 or total > 50 * 1024 * 1024:  # >50 MB em 14 dias = em uso
            continue
        yield ctx.finding(
            title=f"NAT Gateway {gw['NatGatewayId']} praticamente sem tráfego",
            severity=Severity.MEDIUM,
            pillar=Pillar.COST,
            resource_id=gw["NatGatewayId"],
            resource_arn=ctx.arn("ec2", f"natgateway/{gw['NatGatewayId']}"),
            description=(
                f"Saída total de {total / 1048576:.1f} MB em {LOOKBACK_DAYS} dias. O NAT cobra por "
                "hora mesmo ocioso, e é um dos itens mais caros de uma VPC esquecida."
            ),
            remediation=(
                "Se a subnet privada não precisa de internet, remova o NAT. Se o tráfego é só para "
                "serviços AWS, troque por VPC endpoints (S3/ECR/Logs) — normalmente sai mais barato."
            ),
            evidence={"bytes_out": total, "subnet": gw.get("SubnetId")},
            monthly_waste_usd=round(pricing.NAT_GATEWAY_HOUR * pricing.HOURS_PER_MONTH, 2),
            exposure=["empty_resource"],
        )


@check(
    "COST.NO_BUDGET",
    "Conta sem budget configurado",
    Pillar.COST,
    "budgets",
    scope="global",
    well_architected="COST02-BP05",
    permissions=["budgets:DescribeBudgets"],
)
def no_budget(ctx: ScanContext):
    resp = ctx.call("budgets", "describe_budgets", region="us-east-1", AccountId=ctx.account_id)
    if resp is None:
        return
    if not resp.get("Budgets"):
        yield ctx.finding(
            title="Nenhum AWS Budget configurado na conta",
            severity=Severity.LOW,
            pillar=Pillar.COST,
            resource_id=f"budgets:{ctx.account_id}",
            region="global",
            description=(
                "Sem budget com alerta, um recurso provisionado por engano só aparece na fatura "
                "do mês seguinte."
            ),
            remediation="Crie um budget mensal com alertas em 80% e 100% do previsto, e um budget de anomalia por serviço.",
        )

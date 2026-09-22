"""Checks de EC2 / VPC / EBS. Escopo regional."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext, env_exposure, tags_to_dict
from ..models import Pillar, Severity
from ..registry import check

# Portas cujo alcance a partir de 0.0.0.0/0 é quase sempre um erro.
SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker API",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5439: "Redshift",
    5601: "Kibana",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch transport",
    11211: "Memcached",
    27017: "MongoDB",
}


def instances(ctx: ScanContext) -> List[Dict[str, Any]]:
    def _load():
        out = []
        for res in ctx.paginate("ec2", "describe_instances", "Reservations"):
            out.extend(res.get("Instances", []))
        return out

    return ctx.cached("ec2:instances", _load)


def volumes(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached("ec2:volumes", lambda: ctx.paginate("ec2", "describe_volumes", "Volumes"))


def security_groups(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "ec2:sgs", lambda: ctx.paginate("ec2", "describe_security_groups", "SecurityGroups")
    )


def _open_cidrs(perm: Dict[str, Any]) -> List[str]:
    out = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
    out += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
    return out


def _port_range(perm: Dict[str, Any]) -> tuple:
    if perm.get("IpProtocol") == "-1":
        return (0, 65535)
    return (perm.get("FromPort", 0), perm.get("ToPort", 65535))


def _sg_in_use(ctx: ScanContext, group_id: str) -> bool:
    def _load():
        used = set()
        for inst in instances(ctx):
            for sg in inst.get("SecurityGroups", []):
                used.add(sg["GroupId"])
        for eni in ctx.paginate("ec2", "describe_network_interfaces", "NetworkInterfaces"):
            for sg in eni.get("Groups", []):
                used.add(sg["GroupId"])
        return used

    return group_id in ctx.cached("ec2:sgs_in_use", _load)


@check(
    "EC2.SG_OPEN_SENSITIVE_PORT",
    "Porta administrativa aberta para a internet",
    Pillar.SECURITY,
    "ec2",
    well_architected="SEC05-BP01",
    permissions=["ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"],
)
def sg_open_ports(ctx: ScanContext):
    for sg in security_groups(ctx):
        for perm in sg.get("IpPermissions", []):
            cidrs = _open_cidrs(perm)
            if not cidrs:
                continue
            lo, hi = _port_range(perm)
            hits = {p: n for p, n in SENSITIVE_PORTS.items() if lo <= p <= hi}
            if not hits:
                continue
            in_use = _sg_in_use(ctx, sg["GroupId"])
            wide_open = perm.get("IpProtocol") == "-1" or (hi - lo) > 100
            names = ", ".join(f"{n} ({p})" for p, n in sorted(hits.items())[:6])
            yield ctx.finding(
                title=f"Security group '{sg['GroupId']}' expõe {names} para 0.0.0.0/0",
                severity=Severity.CRITICAL if in_use else Severity.HIGH,
                pillar=Pillar.SECURITY,
                resource_id=sg["GroupId"],
                resource_arn=ctx.arn("ec2", f"security-group/{sg['GroupId']}"),
                description=(
                    f"Regra de ingress {lo}-{hi}/{perm.get('IpProtocol')} liberada para {', '.join(cidrs)}"
                    + (" — o grupo está associado a recursos ativos." if in_use else " (grupo sem uso no momento).")
                    + (" A regra abre praticamente toda a faixa de portas." if wide_open else "")
                ),
                remediation=(
                    "Restrinja a origem a prefix lists corporativas ou ao CIDR da VPC. "
                    "Para acesso administrativo, use SSM Session Manager e remova a regra."
                ),
                evidence={
                    "group_name": sg.get("GroupName"),
                    "vpc_id": sg.get("VpcId"),
                    "protocol": perm.get("IpProtocol"),
                    "from_port": lo,
                    "to_port": hi,
                    "attached": in_use,
                },
                exposure=["internet_facing"] if in_use else [],
            )


@check(
    "EC2.DEFAULT_SG_PERMISSIVE",
    "Security group default com regras",
    Pillar.SECURITY,
    "ec2",
    well_architected="SEC05-BP01",
    permissions=["ec2:DescribeSecurityGroups"],
)
def default_sg(ctx: ScanContext):
    for sg in security_groups(ctx):
        if sg.get("GroupName") != "default":
            continue
        if not sg.get("IpPermissions") and len(sg.get("IpPermissionsEgress", [])) <= 1:
            continue
        yield ctx.finding(
            title=f"Security group default da VPC {sg.get('VpcId')} possui regras ativas",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=sg["GroupId"],
            resource_arn=ctx.arn("ec2", f"security-group/{sg['GroupId']}"),
            description=(
                "O SG default é aplicado automaticamente a recursos criados sem SG explícito. "
                "Mantê-lo permissivo cria acesso implícito."
            ),
            remediation="Remova todas as regras de ingress/egress do SG default e crie SGs nomeados por workload.",
            evidence={"ingress_rules": len(sg.get("IpPermissions", []))},
        )


@check(
    "EC2.IMDSV2_NOT_REQUIRED",
    "Instância aceita IMDSv1",
    Pillar.SECURITY,
    "ec2",
    well_architected="SEC06-BP02",
    permissions=["ec2:DescribeInstances"],
)
def imdsv2(ctx: ScanContext):
    for inst in instances(ctx):
        if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
            continue
        meta = inst.get("MetadataOptions", {})
        if meta.get("HttpTokens") == "required" or meta.get("HttpEndpoint") == "disabled":
            continue
        tags = tags_to_dict(inst.get("Tags"))
        has_role = bool(inst.get("IamInstanceProfile"))
        yield ctx.finding(
            title=f"Instância {inst['InstanceId']} não exige IMDSv2",
            severity=Severity.HIGH if has_role else Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=inst["InstanceId"],
            resource_arn=ctx.arn("ec2", f"instance/{inst['InstanceId']}"),
            description=(
                "Com IMDSv1 habilitado, uma falha de SSRF na aplicação permite ler credenciais "
                "temporárias do instance profile via 169.254.169.254."
                + (" A instância tem um IAM role anexado." if has_role else "")
            ),
            remediation=(
                "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required "
                "--http-endpoint enabled. Ajuste também o launch template / AMI base."
            ),
            evidence={"name": tags.get("Name"), "metadata_options": meta},
            exposure=(["privileged_identity"] if has_role else []) + env_exposure(tags),
        )


@check(
    "EC2.EBS_UNENCRYPTED",
    "Volume EBS sem criptografia",
    Pillar.SECURITY,
    "ec2",
    well_architected="SEC08-BP02",
    permissions=["ec2:DescribeVolumes"],
)
def ebs_unencrypted(ctx: ScanContext):
    for vol in volumes(ctx):
        if vol.get("Encrypted"):
            continue
        tags = tags_to_dict(vol.get("Tags"))
        attached = [a["InstanceId"] for a in vol.get("Attachments", [])]
        yield ctx.finding(
            title=f"Volume {vol['VolumeId']} ({vol['Size']} GiB) não está criptografado",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=vol["VolumeId"],
            resource_arn=ctx.arn("ec2", f"volume/{vol['VolumeId']}"),
            description=(
                "Dados em repouso sem criptografia; snapshots derivados também nascem sem proteção."
                + (f" Anexado a {', '.join(attached)}." if attached else " Volume não anexado.")
            ),
            remediation=(
                "Snapshot > copiar snapshot com Encrypted=true > recriar volume > trocar na instância. "
                "Ative EBS encryption by default para impedir novos volumes sem chave."
            ),
            evidence={"attachments": attached, "type": vol.get("VolumeType")},
            exposure=["data_store"] + env_exposure(tags),
        )


@check(
    "EC2.EBS_DEFAULT_ENCRYPTION_OFF",
    "Criptografia padrão de EBS desligada",
    Pillar.SECURITY,
    "ec2",
    well_architected="SEC08-BP02",
    permissions=["ec2:GetEbsEncryptionByDefault"],
)
def ebs_default_encryption(ctx: ScanContext):
    resp = ctx.call("ec2", "get_ebs_encryption_by_default")
    if resp and not resp.get("EbsEncryptionByDefault"):
        yield ctx.finding(
            title=f"EBS encryption by default desabilitado em {ctx.region}",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=f"ebs-default-encryption:{ctx.region}",
            description="Novos volumes e snapshots nascem sem criptografia nesta região.",
            remediation="EC2 > Settings > Data protection and security > Always encrypt new EBS volumes.",
        )


@check(
    "EC2.SNAPSHOT_PUBLIC",
    "Snapshot EBS compartilhado publicamente",
    Pillar.SECURITY,
    "ec2",
    well_architected="SEC01-BP02",
    permissions=["ec2:DescribeSnapshots", "ec2:DescribeSnapshotAttribute"],
)
def public_snapshots(ctx: ScanContext):
    snaps = ctx.cached(
        "ec2:snapshots",
        lambda: ctx.paginate("ec2", "describe_snapshots", "Snapshots", OwnerIds=["self"]),
    )
    for snap in snaps:
        attr = ctx.call(
            "ec2",
            "describe_snapshot_attribute",
            SnapshotId=snap["SnapshotId"],
            Attribute="createVolumePermission",
        )
        if not attr:
            continue
        perms = attr.get("CreateVolumePermissions", [])
        public = any(p.get("Group") == "all" for p in perms)
        shared = [p["UserId"] for p in perms if p.get("UserId")]
        if public:
            yield ctx.finding(
                title=f"Snapshot {snap['SnapshotId']} está público",
                severity=Severity.CRITICAL,
                pillar=Pillar.SECURITY,
                resource_id=snap["SnapshotId"],
                resource_arn=ctx.arn("ec2", f"snapshot/{snap['SnapshotId']}"),
                description="Qualquer conta AWS pode criar um volume a partir deste snapshot e ler os dados.",
                remediation="ec2 modify-snapshot-attribute --operation-type remove --group-names all (imediato).",
                evidence={"description": snap.get("Description"), "volume_size": snap.get("VolumeSize")},
                exposure=["internet_facing", "data_store"],
            )
        elif shared:
            yield ctx.finding(
                title=f"Snapshot {snap['SnapshotId']} compartilhado com contas externas",
                severity=Severity.MEDIUM,
                pillar=Pillar.SECURITY,
                resource_id=snap["SnapshotId"],
                resource_arn=ctx.arn("ec2", f"snapshot/{snap['SnapshotId']}"),
                description=f"Compartilhado com: {', '.join(shared)}.",
                remediation="Valide se o compartilhamento ainda é necessário e revogue o que não for.",
                evidence={"shared_with": shared},
                exposure=["cross_account", "data_store"],
            )


@check(
    "VPC.FLOW_LOGS_DISABLED",
    "VPC sem flow logs",
    Pillar.SECURITY,
    "ec2",
    well_architected="SEC04-BP01",
    permissions=["ec2:DescribeVpcs", "ec2:DescribeFlowLogs"],
)
def flow_logs(ctx: ScanContext):
    vpcs = ctx.paginate("ec2", "describe_vpcs", "Vpcs")
    if not vpcs:
        return
    logs = ctx.paginate("ec2", "describe_flow_logs", "FlowLogs")
    with_logs = {
        fl["ResourceId"] for fl in logs if fl.get("FlowLogStatus") == "ACTIVE"
    }
    for vpc in vpcs:
        if vpc["VpcId"] in with_logs:
            continue
        yield ctx.finding(
            title=f"VPC {vpc['VpcId']} sem flow logs ativos",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=vpc["VpcId"],
            resource_arn=ctx.arn("ec2", f"vpc/{vpc['VpcId']}"),
            description=(
                "Sem flow logs não há como investigar exfiltração, varredura lateral ou "
                "conectividade quebrada depois do incidente."
            ),
            remediation=(
                "Ative flow logs (formato customizado, destino S3 em Parquet para custo menor) "
                "com retenção alinhada à política de resposta a incidentes."
            ),
            evidence={"is_default": vpc.get("IsDefault"), "cidr": vpc.get("CidrBlock")},
        )

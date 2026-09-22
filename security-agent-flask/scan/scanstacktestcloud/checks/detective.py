"""Controles detectivos e de governança: CloudTrail, Config, GuardDuty,
IAM Access Analyzer, Security Hub, KMS e Secrets Manager."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext, days_since
from ..models import Pillar, Severity
from ..registry import check


def region_has_workload(ctx: ScanContext) -> bool:
    """Heurística barata para não gritar em regiões vazias."""

    def _load():
        from .ec2 import instances

        if instances(ctx):
            return True
        fns = ctx.call("lambda", "list_functions", MaxItems=1)
        if fns and fns.get("Functions"):
            return True
        dbs = ctx.call("rds", "describe_db_instances", MaxRecords=20)
        return bool(dbs and dbs.get("DBInstances"))

    return ctx.cached("region:has_workload", _load)


@check(
    "CLOUDTRAIL.NO_MULTI_REGION_TRAIL",
    "Sem trail multi-região",
    Pillar.SECURITY,
    "cloudtrail",
    scope="global",
    well_architected="SEC04-BP01",
    permissions=["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
)
def multi_region_trail(ctx: ScanContext):
    resp = ctx.call("cloudtrail", "describe_trails", region="us-east-1", includeShadowTrails=True)
    trails = (resp or {}).get("trailList", [])
    ctx.cached("cloudtrail:trails", lambda: trails)
    good = []
    for t in trails:
        if not t.get("IsMultiRegionTrail"):
            continue
        status = ctx.call(
            "cloudtrail",
            "get_trail_status",
            region=t.get("HomeRegion", "us-east-1"),
            Name=t["TrailARN"],
        )
        if status and status.get("IsLogging"):
            good.append(t)
    if not good:
        yield ctx.finding(
            title="Nenhum trail multi-região do CloudTrail está ativo",
            severity=Severity.HIGH,
            pillar=Pillar.SECURITY,
            resource_id=f"cloudtrail:{ctx.account_id}",
            region="global",
            description=(
                "Sem trail multi-região ativo, ações de API em regiões não cobertas não são "
                "registradas — inclusive as de um atacante que escolhe justamente essas regiões."
            ),
            remediation=(
                "Crie um trail com IsMultiRegionTrail=true e IncludeGlobalServiceEvents=true, "
                "entregando em um bucket de log account com Object Lock."
            ),
            evidence={"trails_found": len(trails)},
        )


@check(
    "CLOUDTRAIL.WEAK_TRAIL_CONFIG",
    "Trail sem validação ou KMS",
    Pillar.SECURITY,
    "cloudtrail",
    scope="global",
    well_architected="SEC04-BP01",
    permissions=["cloudtrail:DescribeTrails"],
)
def trail_hardening(ctx: ScanContext):
    trails = ctx.cached(
        "cloudtrail:trails",
        lambda: (
            ctx.call("cloudtrail", "describe_trails", region="us-east-1", includeShadowTrails=True)
            or {}
        ).get("trailList", []),
    )
    seen = set()
    for t in trails:
        arn = t.get("TrailARN", "")
        if arn in seen:
            continue
        seen.add(arn)
        gaps = []
        if not t.get("LogFileValidationEnabled"):
            gaps.append("sem validação de integridade dos logs")
        if not t.get("KmsKeyId"):
            gaps.append("sem criptografia com KMS")
        if not t.get("CloudWatchLogsLogGroupArn"):
            gaps.append("sem entrega para CloudWatch Logs (dificulta alarmes em tempo real)")
        if not gaps:
            continue
        yield ctx.finding(
            title=f"Trail '{t.get('Name')}' com hardening incompleto",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=t.get("Name", arn),
            resource_arn=arn,
            region=t.get("HomeRegion", "global"),
            description="; ".join(gaps).capitalize() + ".",
            remediation=(
                "Ative log file validation, aponte uma CMK e envie para um log group com "
                "métricas/alarmes de eventos sensíveis (root login, mudanças de policy)."
            ),
        )


@check(
    "GUARDDUTY.NOT_ENABLED",
    "GuardDuty desabilitado",
    Pillar.SECURITY,
    "guardduty",
    well_architected="SEC04-BP02",
    permissions=["guardduty:ListDetectors"],
)
def guardduty(ctx: ScanContext):
    resp = ctx.call("guardduty", "list_detectors")
    if resp is None:
        return
    if not resp.get("DetectorIds"):
        active = region_has_workload(ctx)
        yield ctx.finding(
            title=f"GuardDuty não habilitado em {ctx.region}",
            severity=Severity.MEDIUM if active else Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=f"guardduty:{ctx.region}",
            description=(
                "Sem GuardDuty não há detecção gerenciada de credenciais usadas fora do padrão, "
                "mineração de cripto, comunicação com C2 ou reconhecimento de API."
                + ("" if active else " A região não aparenta ter workloads — ainda assim, regiões ociosas são alvo comum de abuso.")
            ),
            remediation="Habilite via Organizations (delegated admin) para cobrir todas as contas e regiões automaticamente.",
        )


@check(
    "CONFIG.RECORDER_DISABLED",
    "AWS Config sem gravação",
    Pillar.SECURITY,
    "config",
    well_architected="SEC04-BP01",
    permissions=["config:DescribeConfigurationRecorderStatus"],
)
def config_recorder(ctx: ScanContext):
    resp = ctx.call("config", "describe_configuration_recorder_status")
    if resp is None:
        return
    recorders = resp.get("ConfigurationRecordersStatus", [])
    if not any(r.get("recording") for r in recorders):
        if not region_has_workload(ctx):
            return
        yield ctx.finding(
            title=f"AWS Config não está gravando em {ctx.region}",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=f"config-recorder:{ctx.region}",
            description=(
                "Sem histórico de configuração não há linha do tempo de mudanças nem avaliação "
                "contínua de conformidade — a investigação pós-incidente vira arqueologia."
            ),
            remediation="Habilite o recorder com delivery channel em S3 e conformance packs relevantes.",
        )


@check(
    "ACCESSANALYZER.NOT_ENABLED",
    "IAM Access Analyzer desabilitado",
    Pillar.SECURITY,
    "accessanalyzer",
    well_architected="SEC03-BP07",
    permissions=["access-analyzer:ListAnalyzers"],
)
def access_analyzer(ctx: ScanContext):
    resp = ctx.call("accessanalyzer", "list_analyzers", type="ACCOUNT")
    if resp is None:
        return
    active = [a for a in resp.get("analyzers", []) if a.get("status") == "ACTIVE"]
    if not active and region_has_workload(ctx):
        yield ctx.finding(
            title=f"Access Analyzer não habilitado em {ctx.region}",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=f"access-analyzer:{ctx.region}",
            description="Não há detecção automática de recursos compartilhados com contas externas ou público.",
            remediation="Crie um analyzer com zone of trust na organização — é gratuito.",
        )


@check(
    "KMS.KEY_ROTATION_DISABLED",
    "CMK sem rotação automática",
    Pillar.SECURITY,
    "kms",
    well_architected="SEC08-BP01",
    permissions=["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus"],
)
def kms_rotation(ctx: ScanContext):
    keys = ctx.paginate("kms", "list_keys", "Keys")
    for key in keys:
        desc = ctx.call("kms", "describe_key", KeyId=key["KeyId"])
        if not desc:
            continue
        meta = desc["KeyMetadata"]
        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
            continue
        if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
            continue
        if meta.get("Origin") == "EXTERNAL":
            continue
        status = ctx.call("kms", "get_key_rotation_status", KeyId=key["KeyId"])
        if status and not status.get("KeyRotationEnabled"):
            yield ctx.finding(
                title=f"CMK {key['KeyId']} sem rotação automática",
                severity=Severity.LOW,
                pillar=Pillar.SECURITY,
                resource_id=key["KeyId"],
                resource_arn=meta["Arn"],
                description=(
                    f"Chave '{meta.get('Description') or 'sem descrição'}' usa o mesmo material "
                    "criptográfico indefinidamente."
                ),
                remediation="kms enable-key-rotation — transparente, sem re-criptografar dados existentes.",
            )


@check(
    "SECRETSMANAGER.NO_ROTATION",
    "Secret sem rotação",
    Pillar.SECURITY,
    "secretsmanager",
    well_architected="SEC02-BP05",
    permissions=["secretsmanager:ListSecrets"],
)
def secrets_rotation(ctx: ScanContext):
    secrets = ctx.paginate("secretsmanager", "list_secrets", "SecretList")
    for s in secrets:
        if s.get("RotationEnabled"):
            continue
        age = days_since(s.get("LastChangedDate"))
        if age is not None and age < 90:
            continue
        yield ctx.finding(
            title=f"Secret '{s['Name']}' sem rotação automática",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=s["Name"],
            resource_arn=s["ARN"],
            description=(
                f"Rotação desabilitada e último valor alterado há {age} dias."
                if age is not None
                else "Rotação desabilitada."
            ),
            remediation="Configure rotação com Lambda (para RDS existem templates prontos) ou documente o processo manual.",
            evidence={"age_days": age},
        )

"""Checks de S3. Escopo global: a listagem de buckets é global, mas cada
operação de configuração é feita no endpoint regional correto do bucket."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from ..context import ScanContext
from ..models import Pillar, Severity
from ..registry import check

PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _buckets(ctx: ScanContext) -> List[Dict[str, Any]]:
    """Lista buckets + região de cada um (cacheado por scan)."""

    def _load():
        s3 = ctx.client("s3", region="us-east-1")
        out = []
        for b in s3.list_buckets().get("Buckets", []):
            try:
                loc = s3.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint")
            except ClientError:
                loc = None
            out.append({"Name": b["Name"], "Region": loc or "us-east-1", "CreationDate": b["CreationDate"]})
        ctx.resources_seen += len(out)
        return out

    return ctx.cached("s3:buckets", _load)


def _bclient(ctx: ScanContext, bucket: Dict[str, Any]):
    return ctx.client("s3", region=bucket["Region"])


def _quiet(fn, *codes):
    """Executa e devolve None quando o erro é 'configuração ausente'."""
    try:
        return fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in codes:
            return None
        raise


def _arn(ctx: ScanContext, name: str) -> str:
    return f"arn:{ctx.partition}:s3:::{name}"


@check(
    "S3.ACCOUNT_PUBLIC_ACCESS_BLOCK",
    "Block Public Access da conta incompleto",
    Pillar.SECURITY,
    "s3",
    scope="global",
    well_architected="SEC01-BP02",
    permissions=["s3:GetAccountPublicAccessBlock"],
)
def account_pab(ctx: ScanContext):
    resp = _quiet(
        lambda: ctx.client("s3control", region="us-east-1").get_public_access_block(
            AccountId=ctx.account_id
        ),
        "NoSuchPublicAccessBlockConfiguration",
    )
    cfg = (resp or {}).get("PublicAccessBlockConfiguration", {})
    missing = [k for k in PAB_KEYS if not cfg.get(k)]
    if missing:
        yield ctx.finding(
            title="Block Public Access não está ativo no nível da conta",
            severity=Severity.HIGH,
            pillar=Pillar.SECURITY,
            resource_id=f"s3-account-pab:{ctx.account_id}",
            region="global",
            description=(
                "Sem o bloqueio no nível da conta, qualquer bucket novo pode ser exposto "
                f"publicamente por ACL ou policy. Flags desligadas: {', '.join(missing)}."
            ),
            remediation=(
                "S3 > Block Public Access settings for this account > ative as 4 opções. "
                "Faça antes um inventário de buckets que servem conteúdo público via CloudFront/OAC."
            ),
            exposure=["internet_facing", "data_store"],
        )


@check(
    "S3.BUCKET_PUBLIC",
    "Bucket S3 público",
    Pillar.SECURITY,
    "s3",
    scope="global",
    well_architected="SEC01-BP02",
    permissions=["s3:GetBucketPolicyStatus", "s3:GetBucketAcl"],
)
def bucket_public(ctx: ScanContext):
    for b in _buckets(ctx):
        cli = _bclient(ctx, b)
        status = _quiet(
            lambda: cli.get_bucket_policy_status(Bucket=b["Name"]),
            "NoSuchBucketPolicy",
        )
        public_by_policy = bool(status and status["PolicyStatus"]["IsPublic"])

        acl = _quiet(lambda: cli.get_bucket_acl(Bucket=b["Name"]))
        public_by_acl = False
        for grant in (acl or {}).get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                public_by_acl = True

        if public_by_policy or public_by_acl:
            via = " e ".join(
                x for x in ["bucket policy" if public_by_policy else "", "ACL" if public_by_acl else ""] if x
            )
            yield ctx.finding(
                title=f"Bucket '{b['Name']}' está público",
                severity=Severity.CRITICAL,
                pillar=Pillar.SECURITY,
                resource_id=b["Name"],
                resource_arn=_arn(ctx, b["Name"]),
                region=b["Region"],
                description=f"O bucket é acessível publicamente via {via}.",
                remediation=(
                    "Se for hosting estático, mantenha o bucket privado e sirva por CloudFront com "
                    "Origin Access Control. Caso contrário, ative o Block Public Access no bucket."
                ),
                exposure=["internet_facing", "data_store"],
            )


@check(
    "S3.BUCKET_PUBLIC_ACCESS_BLOCK",
    "Bucket sem Block Public Access",
    Pillar.SECURITY,
    "s3",
    scope="global",
    well_architected="SEC01-BP02",
    permissions=["s3:GetBucketPublicAccessBlock"],
)
def bucket_pab(ctx: ScanContext):
    for b in _buckets(ctx):
        cli = _bclient(ctx, b)
        resp = _quiet(
            lambda: cli.get_public_access_block(Bucket=b["Name"]),
            "NoSuchPublicAccessBlockConfiguration",
        )
        cfg = (resp or {}).get("PublicAccessBlockConfiguration", {})
        missing = [k for k in PAB_KEYS if not cfg.get(k)]
        if missing:
            yield ctx.finding(
                title=f"Bucket '{b['Name']}' sem Block Public Access completo",
                severity=Severity.MEDIUM,
                pillar=Pillar.SECURITY,
                resource_id=b["Name"],
                resource_arn=_arn(ctx, b["Name"]),
                region=b["Region"],
                description=f"Flags ausentes: {', '.join(missing)}. O bucket pode ser exposto por engano.",
                remediation="Ative as 4 flags no bucket, ou aplique o bloqueio no nível da conta.",
                evidence={"configuration": cfg},
                exposure=["data_store"],
            )


@check(
    "S3.DEFAULT_ENCRYPTION",
    "Bucket sem criptografia com KMS",
    Pillar.SECURITY,
    "s3",
    scope="global",
    well_architected="SEC08-BP02",
    permissions=["s3:GetEncryptionConfiguration"],
)
def encryption(ctx: ScanContext):
    for b in _buckets(ctx):
        cli = _bclient(ctx, b)
        resp = _quiet(
            lambda: cli.get_bucket_encryption(Bucket=b["Name"]),
            "ServerSideEncryptionConfigurationNotFoundError",
        )
        rules = (resp or {}).get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        algos = [
            r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") for r in rules
        ]
        if "aws:kms" in algos or "aws:kms:dsse" in algos:
            continue
        # SSE-S3 é o padrão desde 2023: existe criptografia, mas sem controle de chave.
        yield ctx.finding(
            title=f"Bucket '{b['Name']}' sem chave gerenciada (SSE-KMS)",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=b["Name"],
            resource_arn=_arn(ctx, b["Name"]),
            region=b["Region"],
            description=(
                "O bucket usa apenas SSE-S3. Sem KMS não há key policy própria, trilha de uso "
                "da chave no CloudTrail nem possibilidade de revogar acesso via chave."
            ),
            remediation=(
                "Configure SSE-KMS com uma CMK e ative Bucket Keys para conter o custo de "
                "requisições ao KMS. Para dados sem classificação, SSE-S3 pode ser aceito formalmente."
            ),
            evidence={"algorithms": algos or ["AES256 (padrão)"]},
            exposure=["data_store"],
        )


@check(
    "S3.TLS_ONLY_POLICY",
    "Bucket aceita tráfego sem TLS",
    Pillar.SECURITY,
    "s3",
    scope="global",
    well_architected="SEC09-BP02",
    permissions=["s3:GetBucketPolicy"],
)
def tls_only(ctx: ScanContext):
    for b in _buckets(ctx):
        cli = _bclient(ctx, b)
        resp = _quiet(lambda: cli.get_bucket_policy(Bucket=b["Name"]), "NoSuchBucketPolicy")
        enforced = False
        if resp:
            doc = json.loads(resp["Policy"])
            stmts = doc.get("Statement", [])
            stmts = [stmts] if isinstance(stmts, dict) else stmts
            for st in stmts:
                cond = st.get("Condition", {})
                bools = cond.get("Bool", {}) or cond.get("BoolIfExists", {})
                secure = bools.get("aws:SecureTransport")
                if st.get("Effect") == "Deny" and str(secure).lower() == "false":
                    enforced = True
        if not enforced:
            yield ctx.finding(
                title=f"Bucket '{b['Name']}' sem Deny para conexões não-TLS",
                severity=Severity.LOW,
                pillar=Pillar.SECURITY,
                resource_id=b["Name"],
                resource_arn=_arn(ctx, b["Name"]),
                region=b["Region"],
                description="Sem a condição aws:SecureTransport, requisições HTTP em texto claro são aceitas.",
                remediation=(
                    'Adicione um statement Deny com Condition {"Bool": {"aws:SecureTransport": "false"}} '
                    "na bucket policy."
                ),
                exposure=["data_store"],
            )


@check(
    "S3.VERSIONING_DISABLED",
    "Bucket sem versionamento",
    Pillar.RELIABILITY,
    "s3",
    scope="global",
    well_architected="REL09-BP01",
    permissions=["s3:GetBucketVersioning"],
)
def versioning(ctx: ScanContext):
    for b in _buckets(ctx):
        cli = _bclient(ctx, b)
        resp = _quiet(lambda: cli.get_bucket_versioning(Bucket=b["Name"])) or {}
        if resp.get("Status") != "Enabled":
            yield ctx.finding(
                title=f"Bucket '{b['Name']}' sem versionamento",
                severity=Severity.MEDIUM,
                pillar=Pillar.RELIABILITY,
                resource_id=b["Name"],
                resource_arn=_arn(ctx, b["Name"]),
                region=b["Region"],
                description=(
                    "Sem versionamento, um DeleteObject ou PutObject acidental (ou malicioso) é "
                    "irreversível — inclusive para ransomware."
                ),
                remediation=(
                    "Ative versionamento + lifecycle para expirar versões antigas, e considere "
                    "Object Lock em buckets de backup."
                ),
                evidence={"status": resp.get("Status", "Suspended/None")},
                exposure=["data_store"],
            )


@check(
    "S3.ACCESS_LOGGING",
    "Bucket sem access logging",
    Pillar.SECURITY,
    "s3",
    scope="global",
    well_architected="SEC04-BP01",
    permissions=["s3:GetBucketLogging"],
)
def access_logging(ctx: ScanContext):
    targets = set()
    infos = []
    for b in _buckets(ctx):
        cli = _bclient(ctx, b)
        resp = _quiet(lambda: cli.get_bucket_logging(Bucket=b["Name"])) or {}
        enabled = resp.get("LoggingEnabled")
        if enabled:
            targets.add(enabled.get("TargetBucket"))
        infos.append((b, bool(enabled)))
    for b, enabled in infos:
        if enabled or b["Name"] in targets:
            continue
        yield ctx.finding(
            title=f"Bucket '{b['Name']}' sem log de acesso",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=b["Name"],
            resource_arn=_arn(ctx, b["Name"]),
            region=b["Region"],
            description="Sem server access logs ou CloudTrail data events não há trilha de leitura de objetos.",
            remediation=(
                "Ative CloudTrail data events (mais rico e pesquisável) para buckets sensíveis, "
                "ou server access logging para buckets de alto volume."
            ),
        )


@check(
    "S3.MPU_LIFECYCLE",
    "Sem expiração de uploads multipart incompletos",
    Pillar.COST,
    "s3",
    scope="global",
    well_architected="COST04-BP02",
    permissions=["s3:GetLifecycleConfiguration"],
)
def mpu_lifecycle(ctx: ScanContext):
    for b in _buckets(ctx):
        cli = _bclient(ctx, b)
        resp = _quiet(
            lambda: cli.get_bucket_lifecycle_configuration(Bucket=b["Name"]),
            "NoSuchLifecycleConfiguration",
        )
        rules = (resp or {}).get("Rules", [])
        has_mpu = any(
            r.get("Status") == "Enabled" and r.get("AbortIncompleteMultipartUpload")
            for r in rules
        )
        if not has_mpu:
            yield ctx.finding(
                title=f"Bucket '{b['Name']}' sem regra de abort de multipart incompleto",
                severity=Severity.LOW,
                pillar=Pillar.COST,
                resource_id=b["Name"],
                resource_arn=_arn(ctx, b["Name"]),
                region=b["Region"],
                description=(
                    "Partes de uploads interrompidos continuam armazenadas e cobradas "
                    "indefinidamente, e não aparecem na listagem de objetos."
                ),
                remediation="Adicione uma regra de lifecycle com AbortIncompleteMultipartUpload em 7 dias.",
                evidence={"lifecycle_rules": len(rules)},
            )

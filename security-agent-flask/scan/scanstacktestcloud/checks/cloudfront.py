"""Checks de CloudFront. Escopo global: as distribuições são recursos globais.

FSBP CloudFront.1 — default root object configurado.
FSBP CloudFront.5 — logging habilitado.
FSBP CloudFront.6 — AWS WAF habilitado.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..models import Pillar, Severity
from ..registry import check


def distributions(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached("cloudfront:distributions", lambda: _load_distributions(ctx))


def _load_distributions(ctx: ScanContext) -> List[Dict[str, Any]]:
    """list_distributions não tem paginator no botocore; faz paginação manual."""
    client = ctx.client("cloudfront", region="us-east-1")
    out: List[Dict[str, Any]] = []
    marker = None
    while True:
        kwargs = {"MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        resp = client.list_distributions(**kwargs)
        dist_list = resp.get("DistributionList", {})
        out.extend(dist_list.get("Items", []) or [])
        if not dist_list.get("IsTruncated"):
            break
        marker = dist_list.get("NextMarker")
    ctx.resources_seen += len(out)
    return out


def _full_config(ctx: ScanContext, dist_id: str) -> Dict[str, Any]:
    """DistributionConfig completo (DefaultRootObject, Logging) via get_distribution."""

    def _load() -> Dict[str, Any]:
        resp = ctx.call("cloudfront", "get_distribution", region="us-east-1", Id=dist_id)
        return (resp or {}).get("Distribution", {}).get("DistributionConfig", {})

    return ctx.cached(f"cloudfront:config:{dist_id}", _load)


@check(
    "CLOUDFRONT.NO_ROOT_OBJECT",
    "Distribuição CloudFront sem default root object",
    Pillar.SECURITY,
    "cloudfront",
    scope="global",
    well_architected="SEC09-BP02",
    permissions=["cloudfront:ListDistributions", "cloudfront:GetDistribution"],
)
def cf_root_object(ctx: ScanContext):
    """FSBP CloudFront.1 — a distribuição deve ter um default root object."""
    for dist in distributions(ctx):
        cfg = _full_config(ctx, dist["Id"])
        if cfg.get("DefaultRootObject"):
            continue
        yield ctx.finding(
            title=f"Distribuição CloudFront '{dist['Id']}' sem default root object",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=dist["Id"],
            resource_arn=dist["ARN"],
            region="global",
            description=(
                "Sem DefaultRootObject, acessar a raiz do domínio devolve um erro ou o "
                "conteúdo do diretório — em vez de servir o index esperado."
            ),
            remediation="Configure DefaultRootObject (ex.: index.html) na distribuição.",
            evidence={"domain": dist.get("DomainName")},
        )


@check(
    "CLOUDFRONT.NO_LOGGING",
    "Distribuição CloudFront sem logging",
    Pillar.SECURITY,
    "cloudfront",
    scope="global",
    well_architected="SEC04-BP01",
    permissions=["cloudfront:ListDistributions", "cloudfront:GetDistribution"],
)
def cf_logging(ctx: ScanContext):
    """FSBP CloudFront.5 — logging deve estar habilitado na distribuição."""
    for dist in distributions(ctx):
        cfg = _full_config(ctx, dist["Id"])
        logging = cfg.get("Logging", {})
        if logging.get("Enabled") and logging.get("Bucket"):
            continue
        yield ctx.finding(
            title=f"Distribuição CloudFront '{dist['Id']}' sem logging",
            severity=Severity.LOW,
            pillar=Pillar.SECURITY,
            resource_id=dist["Id"],
            resource_arn=dist["ARN"],
            region="global",
            description=(
                "Sem access logs não há como analisar tráfego, detectar abuso ou fazer "
                "forense de requisições na borda."
            ),
            remediation=(
                "Ative logging apontando para um bucket S3 (de preferência com lifecycle e "
                "Object Lock), ou use CloudFront real-time logs com Kinesis."
            ),
            evidence={"domain": dist.get("DomainName")},
        )


@check(
    "CLOUDFRONT.NO_WAF",
    "Distribuição CloudFront sem AWS WAF",
    Pillar.SECURITY,
    "cloudfront",
    scope="global",
    well_architected="SEC09-BP02",
    permissions=["cloudfront:ListDistributions"],
)
def cf_waf(ctx: ScanContext):
    """FSBP CloudFront.6 — a distribuição deve ter um AWS WAF associado."""
    for dist in distributions(ctx):
        if dist.get("WebACLId"):
            continue
        yield ctx.finding(
            title=f"Distribuição CloudFront '{dist['Id']}' sem AWS WAF",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=dist["Id"],
            resource_arn=dist["ARN"],
            region="global",
            description=(
                "Sem WAF, a borda não filtra SQLi, XSS, bots e floods. O CloudFront fica "
                "exposto diretamente à internet sem camada de proteção de aplicação."
            ),
            remediation=(
                "Associe um WebACL (managed rules AWSManagedRulesCommonRuleSet + rate-based "
                "rule) à distribuição."
            ),
            evidence={"domain": dist.get("DomainName")},
            exposure=["internet_facing"],
        )
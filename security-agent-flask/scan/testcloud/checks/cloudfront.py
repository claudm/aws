"""Checks de CloudFront. Escopo global: as distribuições são recursos globais.

FSBP CloudFront.1 — default root object configurado.
FSBP CloudFront.5 — logging habilitado.
FSBP CloudFront.6 — AWS WAF habilitado.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..registry import resource_provider


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


@resource_provider("cloudfront", "distribution")
def iter_distributions(ctx: ScanContext):
    for dist in distributions(ctx):
        yield {
            "resource_id": dist["Id"],
            "region": "global",
            "arn": dist["ARN"],
            "params": {"Id": dist["Id"]},
            "vars": [dist["Id"]],
        }

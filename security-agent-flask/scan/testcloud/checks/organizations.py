"""Checks de AWS Organizations. Escopo global."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("organizations", "organization")
def iter_organization(ctx: ScanContext):
    # Fora de uma organização (ou sem permissão) não há recurso a avaliar.
    try:
        resp = ctx.call("organizations", "describe_organization", region="us-east-1")
    except Exception:
        return
    org = (resp or {}).get("Organization")
    if not org:
        return
    yield {
        "resource_id": org.get("Id", "org"),
        "region": "global",
        "arn": org.get("Arn", ""),
        "params": {},
        "vars": [org.get("Id", "org"), org.get("FeatureSet")],
    }

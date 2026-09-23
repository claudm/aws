"""Checks de Amazon OpenSearch. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("es", "domain")
def iter_domains(ctx: ScanContext):
    resp = ctx.call("es", "list_domain_names")
    for d in (resp or {}).get("DomainNames", []):
        name = d["DomainName"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": ctx.arn("es", f"domain/{name}"),
            "params": {"DomainNames": [name]},
            "vars": [name],
        }

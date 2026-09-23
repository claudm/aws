"""Checks de Amazon Redshift. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("redshift", "cluster")
def iter_clusters(ctx: ScanContext):
    for c in ctx.paginate("redshift", "describe_clusters", "Clusters"):
        name = c["ClusterIdentifier"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": ctx.arn("redshift", f"cluster:{name}"),
            "params": {"ClusterIdentifier": name},
            "vars": [name],
        }

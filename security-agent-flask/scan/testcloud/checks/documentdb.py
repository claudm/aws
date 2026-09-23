"""Checks de Amazon DocumentDB. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("docdb", "cluster")
def iter_clusters(ctx: ScanContext):
    for c in ctx.paginate("docdb", "describe_db_clusters", "DBClusters"):
        if c.get("Engine", "") != "docdb":
            continue
        name = c["DBClusterIdentifier"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": c["DBClusterArn"],
            "params": {"DBClusterIdentifier": name},
            "vars": [name],
        }

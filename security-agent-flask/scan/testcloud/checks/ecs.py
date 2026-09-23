"""Checks de Amazon ECS. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("ecs", "cluster")
def iter_clusters(ctx: ScanContext):
    for arn in ctx.paginate("ecs", "list_clusters", "clusterArns"):
        name = arn.split("/")[-1]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": arn,
            "params": {"clusters": [arn], "include": ["SETTINGS"]},
            "vars": [name],
        }

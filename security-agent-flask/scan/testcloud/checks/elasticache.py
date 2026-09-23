"""Checks de Amazon ElastiCache. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("elasticache", "cluster")
def iter_clusters(ctx: ScanContext):
    for c in ctx.paginate("elasticache", "describe_cache_clusters", "CacheClusters"):
        cid = c["CacheClusterId"]
        yield {
            "resource_id": cid,
            "region": ctx.region,
            "arn": c.get("ARN") or ctx.arn("elasticache", f"cluster:{cid}"),
            "params": {"CacheClusterId": cid},
            "vars": [cid],
        }

"""Checks de Amazon CloudWatch Logs. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("logs", "log_group")
def iter_log_groups(ctx: ScanContext):
    for group in ctx.paginate("logs", "describe_log_groups", "logGroups"):
        name = group["logGroupName"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": group["arn"],
            # O nome exato é sempre o primeiro resultado do prefixo (ordem lexicográfica).
            "params": {"logGroupNamePrefix": name, "limit": 1},
            "vars": [name],
        }

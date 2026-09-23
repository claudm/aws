"""Checks de Amazon Athena. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("athena", "workgroup")
def iter_workgroups(ctx: ScanContext):
    # list_work_groups não tem paginator.
    resp = ctx.call("athena", "list_work_groups")
    for wg in (resp or {}).get("WorkGroups", []):
        name = wg["Name"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": ctx.arn("athena", f"workgroup/{name}"),
            "params": {"WorkGroup": name},
            "vars": [name],
        }

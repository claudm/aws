"""Checks de Amazon EventBridge. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("events", "bus")
def iter_buses(ctx: ScanContext):
    # list_event_buses não tem paginator.
    resp = ctx.call("events", "list_event_buses")
    for bus in (resp or {}).get("EventBuses", []):
        yield {
            "resource_id": bus["Name"],
            "region": ctx.region,
            "arn": bus["Arn"],
            "params": {"Name": bus["Name"]},
            "vars": [bus["Name"]],
        }

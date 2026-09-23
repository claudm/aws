"""Checks de AWS Step Functions. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("states", "state_machine")
def iter_state_machines(ctx: ScanContext):
    for sm in ctx.paginate("stepfunctions", "list_state_machines", "stateMachines"):
        yield {
            "resource_id": sm["name"],
            "region": ctx.region,
            "arn": sm["stateMachineArn"],
            "params": {"stateMachineArn": sm["stateMachineArn"]},
            "vars": [sm["name"]],
        }

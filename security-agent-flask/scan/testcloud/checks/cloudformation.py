"""Checks de AWS CloudFormation. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("cloudformation", "stack")
def iter_stacks(ctx: ScanContext):
    for stack in ctx.paginate("cloudformation", "describe_stacks", "Stacks"):
        status = stack.get("StackStatus", "")
        if "DELETE" in status and status != "DELETE_FAILED":
            continue
        name = stack["StackName"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": stack["StackId"],
            "params": {"StackName": name},
            "vars": [name],
        }

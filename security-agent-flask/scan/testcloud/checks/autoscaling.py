"""Checks de Auto Scaling. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("autoscaling", "group")
def iter_groups(ctx: ScanContext):
    for asg in ctx.paginate("autoscaling", "describe_auto_scaling_groups", "AutoScalingGroups"):
        name = asg["AutoScalingGroupName"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": asg["AutoScalingGroupARN"],
            "params": {"AutoScalingGroupNames": [name]},
            "vars": [name, len(asg.get("AvailabilityZones", []))],
        }

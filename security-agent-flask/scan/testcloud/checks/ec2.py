"""Checks de EC2 / VPC / EBS. Escopo regional."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..registry import resource_provider


def instances(ctx: ScanContext) -> List[Dict[str, Any]]:
    def _load():
        out = []
        for res in ctx.paginate("ec2", "describe_instances", "Reservations"):
            out.extend(res.get("Instances", []))
        return out

    return ctx.cached("ec2:instances", _load)


def volumes(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached("ec2:volumes", lambda: ctx.paginate("ec2", "describe_volumes", "Volumes"))


def security_groups(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "ec2:sgs", lambda: ctx.paginate("ec2", "describe_security_groups", "SecurityGroups")
    )


@resource_provider("ec2", "security_group")
def iter_security_groups(ctx: ScanContext):
    for sg in security_groups(ctx):
        yield {
            "resource_id": sg["GroupId"],
            "region": ctx.region,
            "arn": ctx.arn("ec2", f"security-group/{sg['GroupId']}"),
            "params": {"GroupIds": [sg["GroupId"]]},
            "vars": [sg["GroupId"]],
        }


@resource_provider("ec2", "instance")
def iter_instances(ctx: ScanContext):
    for inst in instances(ctx):
        yield {
            "resource_id": inst["InstanceId"],
            "region": ctx.region,
            "arn": ctx.arn("ec2", f"instance/{inst['InstanceId']}"),
            "params": {"InstanceIds": [inst["InstanceId"]]},
            "vars": [inst["InstanceId"]],
        }


@resource_provider("ec2", "volume")
def iter_volumes(ctx: ScanContext):
    for vol in volumes(ctx):
        yield {
            "resource_id": vol["VolumeId"],
            "region": ctx.region,
            "arn": ctx.arn("ec2", f"volume/{vol['VolumeId']}"),
            "params": {"VolumeIds": [vol["VolumeId"]]},
            "vars": [vol["VolumeId"]],
        }


@resource_provider("ec2", "region")
def iter_region(ctx: ScanContext):
    yield {
        "resource_id": f"ebs-default-encryption:{ctx.region}",
        "region": ctx.region,
        "params": {},
    }


@resource_provider("ec2", "snapshot")
def iter_snapshots(ctx: ScanContext):
    snaps = ctx.cached(
        "ec2:snapshots",
        lambda: ctx.paginate("ec2", "describe_snapshots", "Snapshots", OwnerIds=["self"]),
    )
    for snap in snaps:
        yield {
            "resource_id": snap["SnapshotId"],
            "region": ctx.region,
            "arn": ctx.arn("ec2", f"snapshot/{snap['SnapshotId']}"),
            "params": {"SnapshotId": snap["SnapshotId"]},
            "vars": [snap["SnapshotId"]],
        }


@resource_provider("ec2", "vpc")
def iter_vpcs(ctx: ScanContext):
    for vpc in ctx.paginate("ec2", "describe_vpcs", "Vpcs"):
        yield {
            "resource_id": vpc["VpcId"],
            "region": ctx.region,
            "arn": ctx.arn("ec2", f"vpc/{vpc['VpcId']}"),
            "params": {"Filters": [{"Name": "resource-id", "Values": [vpc["VpcId"]]}]},
            "vars": [vpc["VpcId"]],
        }

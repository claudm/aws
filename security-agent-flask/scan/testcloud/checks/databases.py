"""Checks de bancos gerenciados: RDS, Aurora e DynamoDB. Escopo regional."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..registry import resource_provider


def db_instances(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "rds:instances", lambda: ctx.paginate("rds", "describe_db_instances", "DBInstances")
    )


def db_clusters(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "rds:clusters", lambda: ctx.paginate("rds", "describe_db_clusters", "DBClusters")
    )


@resource_provider("rds", "instance")
def iter_instances(ctx: ScanContext):
    for db in db_instances(ctx):
        name = db["DBInstanceIdentifier"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": db["DBInstanceArn"],
            "params": {"DBInstanceIdentifier": name},
            "vars": [name],
        }


@resource_provider("rds", "cluster")
def iter_clusters(ctx: ScanContext):
    for c in db_clusters(ctx):
        name = c["DBClusterIdentifier"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": c["DBClusterArn"],
            "params": {"DBClusterIdentifier": name},
            "vars": [name],
        }


@resource_provider("rds", "snapshot")
def iter_snapshots(ctx: ScanContext):
    for snap in ctx.paginate("rds", "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
        name = snap["DBSnapshotIdentifier"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": snap["DBSnapshotArn"],
            "params": {"DBSnapshotIdentifier": name},
            "vars": [name],
        }


@resource_provider("rds", "cluster_snapshot")
def iter_cluster_snapshots(ctx: ScanContext):
    for snap in ctx.paginate("rds", "describe_db_cluster_snapshots", "DBClusterSnapshots", SnapshotType="manual"):
        name = snap["DBClusterSnapshotIdentifier"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": snap["DBClusterSnapshotArn"],
            "params": {"DBClusterSnapshotIdentifier": name},
            "vars": [name],
        }


@resource_provider("dynamodb", "table")
def iter_tables(ctx: ScanContext):
    for name in ctx.cached("ddb:tables", lambda: ctx.paginate("dynamodb", "list_tables", "TableNames")):
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": ctx.arn("dynamodb", f"table/{name}"),
            "params": {"TableName": name},
            "vars": [name],
        }

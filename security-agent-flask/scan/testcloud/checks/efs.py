"""Checks de Amazon EFS. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("efs", "file_system")
def iter_file_systems(ctx: ScanContext):
    for fs in ctx.paginate("efs", "describe_file_systems", "FileSystems"):
        fs_id = fs["FileSystemId"]
        yield {
            "resource_id": fs_id,
            "region": ctx.region,
            "arn": ctx.arn("elasticfilesystem", f"file-system/{fs_id}"),
            "params": {"FileSystemId": fs_id},
            "vars": [fs_id],
        }

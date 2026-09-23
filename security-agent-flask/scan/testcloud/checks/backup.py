"""Checks de AWS Backup. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("backup", "vault")
def iter_vaults(ctx: ScanContext):
    for v in ctx.paginate("backup", "list_backup_vaults", "BackupVaultList"):
        name = v["BackupVaultName"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": v["BackupVaultArn"],
            "params": {"BackupVaultName": name},
            "vars": [name],
        }

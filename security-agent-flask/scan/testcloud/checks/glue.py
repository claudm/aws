"""Checks de AWS Glue. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("glue", "account")
def iter_account(ctx: ScanContext):
    yield {
        "resource_id": f"glue-catalog-{ctx.account_id}",
        "region": ctx.region,
        "arn": ctx.arn("glue", "catalog"),
        "params": {},
    }

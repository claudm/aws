"""Checks de Amazon EMR. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("emr", "account")
def iter_account(ctx: ScanContext):
    yield {
        "resource_id": f"emr-bpa-{ctx.region}",
        "region": ctx.region,
        "arn": ctx.arn("emr", "block-public-access"),
        "params": {},
    }

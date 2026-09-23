"""Checks de Amazon Macie. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("macie2", "account")
def iter_account(ctx: ScanContext):
    yield {
        "resource_id": f"macie:{ctx.region}",
        "region": ctx.region,
        "arn": ctx.arn("macie2", "session"),
        "params": {},
        "vars": [ctx.region],
    }

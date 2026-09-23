"""Checks de Amazon Bedrock. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("bedrock", "account")
def iter_account(ctx: ScanContext):
    yield {
        "resource_id": f"bedrock-logging-{ctx.account_id}",
        "region": ctx.region,
        "arn": ctx.arn("bedrock", "logging"),
        "params": {},
    }

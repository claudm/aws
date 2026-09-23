"""Checks de AWS Systems Manager. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("ssm", "session_manager")
def iter_session_manager(ctx: ScanContext):
    yield {
        "resource_id": "SSM-SessionManagerRunShell",
        "region": ctx.region,
        "arn": ctx.arn("ssm", "document/SSM-SessionManagerRunShell"),
        "params": {},
    }

"""Checks de Amazon Kinesis. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("kinesis", "stream")
def iter_streams(ctx: ScanContext):
    for name in ctx.paginate("kinesis", "list_streams", "StreamNames"):
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": ctx.arn("kinesis", f"stream/{name}"),
            "params": {"StreamName": name},
            "vars": [name],
        }

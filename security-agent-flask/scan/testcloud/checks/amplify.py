"""Checks de AWS Amplify. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("amplify", "app")
def iter_apps(ctx: ScanContext):
    for app in ctx.paginate("amplify", "list_apps", "apps"):
        yield {
            "resource_id": app.get("appId") or app.get("name"),
            "region": ctx.region,
            "arn": app.get("appArn", ""),
            "params": {"appId": app["appId"]},
            "vars": [app.get("name")],
        }

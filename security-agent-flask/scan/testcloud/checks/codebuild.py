"""Checks de AWS CodeBuild. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("codebuild", "project")
def iter_projects(ctx: ScanContext):
    for name in ctx.paginate("codebuild", "list_projects", "projects"):
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": ctx.arn("codebuild", f"project/{name}"),
            "params": {"names": [name]},
            "vars": [name],
        }

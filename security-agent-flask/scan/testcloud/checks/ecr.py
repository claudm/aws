"""Checks de Amazon ECR. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("ecr", "repository")
def iter_repositories(ctx: ScanContext):
    for repo in ctx.paginate("ecr", "describe_repositories", "repositories"):
        name = repo["repositoryName"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": repo["repositoryArn"],
            "params": {"repositoryNames": [name]},
            "vars": [name],
        }

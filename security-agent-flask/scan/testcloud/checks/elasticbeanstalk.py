"""Checks de AWS Elastic Beanstalk. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("elasticbeanstalk", "environment")
def iter_environments(ctx: ScanContext):
    for env in ctx.paginate("elasticbeanstalk", "describe_environments", "Environments"):
        if env.get("Status") in ["Terminating", "Terminated"]:
            continue
        name = env.get("EnvironmentName")
        yield {
            "resource_id": env.get("EnvironmentId") or name,
            "region": ctx.region,
            "arn": env.get("EnvironmentArn", ""),
            "params": {"ApplicationName": env.get("ApplicationName"), "EnvironmentName": name},
            "vars": [name],
        }

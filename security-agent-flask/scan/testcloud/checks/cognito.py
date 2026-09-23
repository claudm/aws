"""Checks de Amazon Cognito. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("cognito-idp", "user_pool")
def iter_user_pools(ctx: ScanContext):
    for pool in ctx.paginate("cognito-idp", "list_user_pools", "UserPools", MaxResults=60):
        pool_id = pool["Id"]
        yield {
            "resource_id": pool_id,
            "region": ctx.region,
            "arn": ctx.arn("cognito-idp", f"userpool/{pool_id}"),
            "params": {"UserPoolId": pool_id},
            "vars": [pool["Name"]],
        }

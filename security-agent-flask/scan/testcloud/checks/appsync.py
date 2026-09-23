"""Checks de AWS AppSync. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("appsync", "graphql_api")
def iter_graphql_apis(ctx: ScanContext):
    for api in ctx.paginate("appsync", "list_graphql_apis", "graphqlApis"):
        yield {
            "resource_id": api["apiId"],
            "region": ctx.region,
            "arn": api["arn"],
            "params": {"apiId": api["apiId"]},
            "vars": [api["name"]],
        }

"""Checks de API Gateway. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("apigateway", "stage")
def iter_stages(ctx: ScanContext):
    """Um recurso por stage de cada REST API (API Gateway V1)."""
    for api in ctx.paginate("apigateway", "get_rest_apis", "items"):
        api_id = api["id"]
        stages = ctx.call("apigateway", "get_stages", restApiId=api_id)
        for stage in (stages or {}).get("item", []):
            name = stage["stageName"]
            yield {
                "resource_id": f"{api_id}/{name}",
                "region": ctx.region,
                "arn": ctx.arn("apigateway", f"/restapis/{api_id}/stages/{name}"),
                "params": {"restApiId": api_id, "stageName": name},
                "vars": [api.get("name", api_id), name],
            }

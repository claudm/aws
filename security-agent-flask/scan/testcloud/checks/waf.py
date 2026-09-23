"""Checks de AWS WAFv2. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("wafv2", "web_acl")
def iter_web_acls(ctx: ScanContext):
    # list_web_acls não tem paginator.
    resp = ctx.call("wafv2", "list_web_acls", Scope="REGIONAL")
    for acl in (resp or {}).get("WebACLs", []):
        yield {
            "resource_id": acl["Name"],
            "region": ctx.region,
            "arn": acl["ARN"],
            "params": {"ResourceArn": acl["ARN"]},
            "vars": [acl["Name"]],
        }

"""Checks de Amazon SES (Simple Email Service). Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("ses", "identity")
def iter_domain_identities(ctx: ScanContext):
    resp = ctx.call("ses", "list_identities", IdentityType="Domain")
    for identity in (resp or {}).get("Identities", []):
        yield {
            "resource_id": identity,
            "region": ctx.region,
            "arn": ctx.arn("ses", f"identity/{identity}"),
            "params": {"Identities": [identity]},
            "vars": [identity],
        }

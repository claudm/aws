"""Checks de Amazon Route53. Escopo global."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("route53", "hosted_zone")
def iter_hosted_zones(ctx: ScanContext):
    for zone in ctx.paginate("route53", "list_hosted_zones", "HostedZones"):
        zone_id = zone["Id"].split("/")[-1]
        yield {
            "resource_id": zone_id,
            "region": ctx.region,
            "arn": ctx.arn("route53", f"hostedzone/{zone_id}", region=""),
            "params": {"HostedZoneId": zone["Id"]},
            "vars": [zone["Name"]],
        }

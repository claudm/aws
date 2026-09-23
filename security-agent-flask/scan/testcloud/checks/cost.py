"""Checks de otimização de custo. Todas as estimativas são aproximações
mensais em USD, usadas para ordenar o que atacar primeiro."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("ec2", "gp2_fleet")
def iter_gp2_fleet(ctx: ScanContext):
    yield {"resource_id": f"gp2-fleet:{ctx.region}", "region": ctx.region, "params": {}}


@resource_provider("ec2", "snapshot_fleet")
def iter_snapshot_fleet(ctx: ScanContext):
    yield {"resource_id": f"stale-snapshots:{ctx.region}", "region": ctx.region, "params": {}}


@resource_provider("ec2", "address")
def iter_addresses(ctx: ScanContext):
    resp = ctx.call("ec2", "describe_addresses")
    for addr in (resp or {}).get("Addresses", []):
        alloc = addr.get("AllocationId", addr.get("PublicIp", ""))
        yield {
            "resource_id": alloc,
            "region": ctx.region,
            "arn": ctx.arn("ec2", f"elastic-ip/{addr.get('AllocationId')}"),
            "params": {"PublicIps": [addr["PublicIp"]]},
            "vars": [addr.get("PublicIp")],
        }


@resource_provider("ec2", "nat_gateway")
def iter_nat_gateways(ctx: ScanContext):
    for gw in ctx.paginate("ec2", "describe_nat_gateways", "NatGateways"):
        gw_id = gw["NatGatewayId"]
        yield {
            "resource_id": gw_id,
            "region": ctx.region,
            "arn": ctx.arn("ec2", f"natgateway/{gw_id}"),
            "params": {"NatGatewayIds": [gw_id]},
            "vars": [gw_id],
        }


@resource_provider("budgets", "account")
def iter_budgets_account(ctx: ScanContext):
    yield {"resource_id": f"budgets:{ctx.account_id}", "region": "global", "params": {}}

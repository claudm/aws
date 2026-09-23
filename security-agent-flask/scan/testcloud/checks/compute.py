"""Checks de Lambda, ECR, EKS e Elastic Load Balancing. Escopo regional."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext, tags_to_dict
from ..registry import resource_provider


def load_balancers(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "elbv2:lbs", lambda: ctx.paginate("elbv2", "describe_load_balancers", "LoadBalancers")
    )


@resource_provider("eks", "cluster")
def iter_eks_clusters(ctx: ScanContext):
    for name in ctx.cached("eks:clusters", lambda: ctx.paginate("eks", "list_clusters", "clusters")):
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": ctx.arn("eks", f"cluster/{name}"),
            "params": {"name": name},
            "vars": [name],
        }


@resource_provider("elbv2", "load_balancer")
def iter_load_balancers(ctx: ScanContext):
    for lb in load_balancers(ctx):
        yield {
            "resource_id": lb["LoadBalancerName"],
            "region": ctx.region,
            "arn": lb["LoadBalancerArn"],
            "params": {"LoadBalancerArn": lb["LoadBalancerArn"]},
            "vars": [lb["LoadBalancerName"]],
        }

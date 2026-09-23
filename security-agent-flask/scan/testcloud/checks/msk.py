"""Checks de Amazon MSK (Kafka). Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("kafka", "cluster")
def iter_clusters(ctx: ScanContext):
    """Só clusters provisionados: serverless sempre usa TLS."""
    for c in ctx.paginate("kafka", "list_clusters_v2", "ClusterInfoList"):
        if "Provisioned" not in c:
            continue
        in_transit = c["Provisioned"].get("EncryptionInfo", {}).get("EncryptionInTransit", {})
        yield {
            "resource_id": c["ClusterName"],
            "region": ctx.region,
            "arn": c["ClusterArn"],
            "params": {"ClusterArn": c["ClusterArn"]},
            "vars": [c["ClusterName"], in_transit.get("ClientBroker", "PLAINTEXT"), in_transit.get("InCluster", False)],
        }

"""Checks de Amazon MQ. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("mq", "broker")
def iter_brokers(ctx: ScanContext):
    for b in ctx.paginate("mq", "list_brokers", "BrokerSummaries"):
        yield {
            "resource_id": b["BrokerName"],
            "region": ctx.region,
            "arn": b["BrokerArn"],
            "params": {"BrokerId": b["BrokerId"]},
            "vars": [b["BrokerName"]],
        }

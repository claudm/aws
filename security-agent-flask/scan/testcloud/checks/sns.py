"""Checks de SNS. Escopo regional.

FSBP SNS.1 — tópicos SNS devem ser criptografados em repouso com AWS KMS.
"""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("sns", "topic")
def iter_topics(ctx: ScanContext):
    for t in ctx.cached("sns:topics", lambda: ctx.paginate("sns", "list_topics", "Topics")):
        arn = t["TopicArn"]
        name = arn.split(":")[-1]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": arn,
            "params": {"TopicArn": arn},
            "vars": [name],
        }

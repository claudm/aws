"""Checks de SQS. Escopo regional.

FSBP SQS.1 — filas SQS devem ser criptografadas em repouso com AWS KMS.
"""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("sqs", "queue")
def iter_queues(ctx: ScanContext):
    for url in ctx.cached("sqs:queues", lambda: ctx.paginate("sqs", "list_queues", "QueueUrls")):
        name = url.rstrip("/").split("/")[-1]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": ctx.arn("sqs", name),
            "params": {"QueueUrl": url, "AttributeNames": ["All"]},
            "vars": [name],
        }

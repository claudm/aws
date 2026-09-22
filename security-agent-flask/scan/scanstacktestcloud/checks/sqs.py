"""Checks de SQS. Escopo regional.

FSBP SQS.1 — filas SQS devem ser criptografadas em repouso com AWS KMS.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..models import Pillar, Severity
from ..registry import check


def queues(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "sqs:queues", lambda: ctx.paginate("sqs", "list_queues", "QueueUrls")
    )


@check(
    "SQS.NOT_ENCRYPTED",
    "Fila SQS sem criptografia KMS",
    Pillar.SECURITY,
    "sqs",
    well_architected="SEC08-BP02",
    permissions=["sqs:ListQueues", "sqs:GetQueueAttributes"],
)
def sqs_encryption(ctx: ScanContext):
    """FSBP SQS.1 — filas devem usar KMS para criptografia em repouso."""
    for url in queues(ctx):
        attrs = ctx.call(
            "sqs", "get_queue_attributes", QueueUrl=url, AttributeNames=["All"]
        )
        if not attrs:
            continue
        attributes = attrs.get("Attributes", {})
        if attributes.get("KmsMasterKeyId"):
            continue
        name = url.rstrip("/").split("/")[-1]
        yield ctx.finding(
            title=f"Fila SQS '{name}' sem criptografia KMS",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=name,
            resource_arn=ctx.arn("sqs", name),
            description=(
                "Sem KmsMasterKeyId, as mensagens são criptografadas com a chave gerenciada "
                "pela AWS (aws/sqs). Sem uma CMK não há controle de quem pode descriptografar "
                "nem trilha de uso da chave no CloudTrail."
            ),
            remediation=(
                "Crie uma CMK e associe à fila (KmsMasterKeyId). A key policy precisa "
                "permitir sqs:SendMessage e sqs:ReceiveMessage para o serviço SQS."
            ),
            evidence={"visibility_timeout": attributes.get("VisibilityTimeout")},
            exposure=["data_store"],
        )
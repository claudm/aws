"""Checks de SNS. Escopo regional.

FSBP SNS.1 — tópicos SNS devem ser criptografados em repouso com AWS KMS.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..models import Pillar, Severity
from ..registry import check


def topics(ctx: ScanContext) -> List[Dict[str, Any]]:
    return ctx.cached(
        "sns:topics", lambda: ctx.paginate("sns", "list_topics", "Topics")
    )


@check(
    "SNS.NOT_ENCRYPTED",
    "Tópico SNS sem criptografia KMS",
    Pillar.SECURITY,
    "sns",
    well_architected="SEC08-BP02",
    permissions=["sns:ListTopics", "sns:GetTopicAttributes"],
)
def sns_encryption(ctx: ScanContext):
    """FSBP SNS.1 — tópicos devem usar KMS para criptografia em repouso."""
    for t in topics(ctx):
        arn = t["TopicArn"]
        attrs = ctx.call("sns", "get_topic_attributes", TopicArn=arn)
        if not attrs:
            continue
        attributes = attrs.get("Attributes", {})
        if attributes.get("KmsMasterKeyId"):
            continue
        yield ctx.finding(
            title=f"Tópico SNS '{arn.split(':')[-1]}' sem criptografia KMS",
            severity=Severity.MEDIUM,
            pillar=Pillar.SECURITY,
            resource_id=arn.split(":")[-1],
            resource_arn=arn,
            description=(
                "Sem KmsMasterKeyId, as mensagens são criptografadas com a chave gerenciada "
                "pela AWS (aws/sns). Sem uma CMK não há controle de quem pode descriptografar "
                "nem trilha de uso da chave no CloudTrail."
            ),
            remediation=(
                "Crie uma CMK e associe ao tópico (KmsMasterKeyId). A key policy precisa "
                "permitir sns:Publish e sns:Subscribe para o serviço SNS."
            ),
            evidence={"display_name": attributes.get("DisplayName")},
            exposure=["data_store"],
        )
"""Backend de produção: o serviço AWS Security Agent.

Cobre só o que o moto não sabe fazer e por isso precisa de duas versões — o
domínio (Spaces/Pentests/Endpoints) e o presign de upload. EC2, IAM, S3 e
Secrets Manager têm implementação única em `aws.py`, usada nos dois ambientes.

Espelha `backends.memory` função por função; a escolha é de
`backends.get_backend()`.
"""
from __future__ import annotations

import logging

from botocore.exceptions import BotoCoreError, ClientError

from .. import securityagent
from ..aws import (
    _artifact_key,
    _aws_error,
    _client,
    assume_cross_account,
    validate_role_arn_account,
)
from ..config import get_settings
from ..errors import ApiError
from ..schemas import (
    CreateSpaceRequest,
    Pentest,
    PentestCreate,
    PentestUpdate,
    PresignUploadResponse,
    Space,
    UpdateSpaceRequest,
    VerifiedEndpoint,
)

logger = logging.getLogger("security-agent.backend.real")


# ---- Spaces ----
def list_spaces(account_id: str, region: str) -> list[Space]:
    assume_cross_account(account_id, region)
    return securityagent.list_agent_spaces(region, account_id)


def get_space(space_id: str) -> Space:
    s = get_settings()
    sp = securityagent.get_agent_space(s.aws_region, space_id, s.expected_account_id or "")
    if not sp:
        raise ApiError(404, f"Space '{space_id}' não encontrado")
    return sp


def create_space(account_id: str, region: str, body: CreateSpaceRequest) -> Space:
    return securityagent.create_agent_space(
        region, account_id, name=body.name, description=body.description,
        aws_resources=body.aws_resources, target_domain_ids=body.target_domain_ids or None,
        code_review_settings=body.code_review_settings, kms_key_id=body.kms_key_id,
        tags=body.tags or None,
    )


def update_space(space_id: str, body: UpdateSpaceRequest) -> Space:
    settings = get_settings()
    sent = body.model_fields_set

    def field(name: str):
        return getattr(body, name) if name in sent else None

    return securityagent.update_agent_space(
        settings.aws_region, settings.expected_account_id or "", space_id,
        name=field("name"), description=field("description"),
        aws_resources=field("aws_resources"), target_domain_ids=field("target_domain_ids"),
        code_review_settings=field("code_review_settings"), tags=field("tags"),
    )


def delete_space(space_id: str) -> dict:
    raise ApiError(501, "Remoção de Space não é suportada no modo securityagent.")


# ---- Pentests ----
def list_pentests(space: Space) -> list[Pentest]:
    return securityagent.list_pentests(space.region, space.space_id)


def get_pentest(pentest_id: str) -> Pentest:
    """Não suportado: BatchGetPentests exige o agentSpaceId, que esta rota não
    recebe. A listagem por Space (`list_pentests`) cobre o caso de uso do front.
    """
    raise ApiError(404, f"Pentest '{pentest_id}' não encontrado")


def create_pentest(space: Space, body: PentestCreate) -> Pentest:
    validate_role_arn_account(space.account_id, body.target.service_role_arn)
    return securityagent.create_pentest(
        space.region, space.account_id, space.space_id, body.title,
        body.target.endpoints, body.network, body.target.service_role_arn,
        body.resources,
    )


def start_pentest(pentest_id: str, space_id: str | None) -> dict:
    """Inicia a execução — CreatePentest só registra o recurso.

    O serviço devolve apenas o status do job (o `memory` devolve o pentest
    inteiro; o front lê só `status` nos dois casos).
    """
    if not space_id:
        raise ApiError(400, "Parâmetro 'space_id' é obrigatório")
    space = get_space(space_id)
    status = securityagent.start_pentest_job(space.region, space.space_id, pentest_id)
    return {"id": pentest_id, "status": status.value}


def update_pentest(pentest_id: str, body: PentestUpdate) -> Pentest:
    if not body.space_id:
        raise ApiError(400, "Parâmetro 'space_id' é obrigatório")
    space = get_space(body.space_id)
    if body.target is not None:
        validate_role_arn_account(space.account_id, body.target.service_role_arn)
    return securityagent.update_pentest(
        space.region, space.account_id, space.space_id, pentest_id,
        body.title, body.target.endpoints if body.target else None,
        body.network, body.target.service_role_arn if body.target else None,
        body.resources,
    )


def delete_pentest(pentest_id: str) -> dict:
    raise ApiError(501, "Remoção de Pentest não é suportada no modo securityagent.")


# ---- Endpoints (target domains) ----
def list_endpoints(space: Space) -> list[VerifiedEndpoint]:
    return securityagent.list_endpoints_for_space(space)


def create_endpoint(space: Space, url: str, verification_method: str = "DNS_TXT") -> VerifiedEndpoint:
    endpoint = securityagent.create_target_domain(space.region, url, verification_method)
    if endpoint.id and endpoint.id not in space.target_domain_ids:
        space.target_domain_ids.append(endpoint.id)
    return endpoint


def create_standalone_endpoint(region: str, url: str, verification_method: str = "DNS_TXT") -> VerifiedEndpoint:
    """Alvo criado antes de o Space existir: vira um target domain de verdade,
    com id — associável depois via CreateSpaceRequest.target_domain_ids."""
    return securityagent.create_target_domain(region, url, verification_method)


def verify_endpoint(space: Space, url: str, target_domain_id: str | None = None) -> VerifiedEndpoint:
    tid = target_domain_id or securityagent.resolve_target_domain(space.region, url)
    if not tid:
        raise ApiError(404, "Target domain não encontrado para este endpoint.")
    return securityagent.verify_target_domain(space.region, tid)


# ---- S3 ----
def presign_upload(
    region: str, account_id: str, space_id: str, filename: str, content_type: str | None
) -> PresignUploadResponse:
    settings = get_settings()
    bucket = settings.s3_artifacts_bucket
    key = _artifact_key(account_id, space_id, filename)
    params = {"Bucket": bucket, "Key": key}
    if content_type:
        params["ContentType"] = content_type
    try:
        url = _client("s3", region).generate_presigned_url("put_object", Params=params, ExpiresIn=3600)
    except (ClientError, BotoCoreError) as exc:
        raise _aws_error(exc, "Falha ao gerar URL de upload S3")
    return PresignUploadResponse(
        url=url, content_type=content_type, key=key, s3_uri=f"s3://{bucket}/{key}"
    )

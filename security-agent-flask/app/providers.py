"""Fonte de dados de Spaces/Pentests/Endpoints.

Alterna entre a API real (securityagent) e o store em memória (dev), conforme
SA_BACKEND. Os blueprints falam só com este módulo para leituras/escritas de
domínio; recursos de rede (EC2), IAM e S3 continuam direto na camada aws.py.
"""
from __future__ import annotations

from .config import get_settings
from .errors import ApiError
from .schemas import (
    CreateSpaceRequest,
    Pentest,
    Space,
    UpdateSpaceRequest,
    VerifiedEndpoint,
)
from .store import get_store


def _sa() -> bool:
    return get_settings().sa_backend == "securityagent"


# ---- Spaces ----
def list_spaces(account_id: str, region: str) -> list[Space]:
    if _sa():
        from . import securityagent
        return securityagent.list_agent_spaces(region, account_id)
    return get_store().list_spaces(account_id, region)


def get_space(space_id: str) -> Space:
    s = get_settings()
    if _sa():
        from . import securityagent
        sp = securityagent.get_agent_space(
            s.aws_region, space_id, s.expected_account_id or ""
        )
    else:
        sp = get_store().get_space(space_id)
    if not sp:
        raise ApiError(404, f"Space '{space_id}' não encontrado")
    return sp


def create_space(account_id: str, region: str, body: CreateSpaceRequest) -> Space:
    if _sa():
        from . import securityagent
        return securityagent.create_agent_space(
            region, account_id, name=body.name, description=body.description,
            aws_resources=body.aws_resources, target_domain_ids=body.target_domain_ids or None,
            code_review_settings=body.code_review_settings, kms_key_id=body.kms_key_id,
            tags=body.tags or None,
        )
    # memory
    from uuid import uuid4
    sp = Space(space_id=f"as-{uuid4().hex[:8]}", name=body.name, description=body.description,
               account_id=account_id, region=region,
               endpoints=[VerifiedEndpoint(url=u) for u in body.endpoints],
               target_domain_ids=list(body.target_domain_ids),
               aws_resources=body.aws_resources, tags=dict(body.tags))
    return get_store().upsert_space(sp)


def update_space(space_id: str, body: UpdateSpaceRequest) -> Space:
    """Edição parcial: só os campos presentes no corpo do PATCH são aplicados."""
    settings = get_settings()
    sent = body.model_fields_set

    def field(name: str):
        return getattr(body, name) if name in sent else None

    if _sa():
        from . import securityagent
        return securityagent.update_agent_space(
            settings.aws_region, settings.expected_account_id or "", space_id,
            name=field("name"), description=field("description"),
            aws_resources=field("aws_resources"), target_domain_ids=field("target_domain_ids"),
            code_review_settings=field("code_review_settings"), tags=field("tags"),
        )

    # memory
    space = get_store().get_space(space_id)
    if not space:
        raise ApiError(404, f"Space '{space_id}' não encontrado")
    data: dict = {}
    for name in ("name", "description", "aws_resources", "target_domain_ids", "tags"):
        if name in sent:
            data[name] = getattr(body, name)
    if "endpoints" in sent:
        data["endpoints"] = _merge_endpoints(space.endpoints, body.endpoints or [])
    return get_store().upsert_space(space.model_copy(update=data))


def _merge_endpoints(current: list[VerifiedEndpoint], urls: list[str]) -> list[VerifiedEndpoint]:
    """Aplica a nova lista de URLs preservando o status já verificado das antigas."""
    by_url = {e.url: e for e in current}
    return [by_url.get(u) or VerifiedEndpoint(url=u) for u in urls]


# ---- Pentests ----
def list_pentests(space: Space) -> list[Pentest]:
    if _sa():
        from . import securityagent
        return securityagent.list_pentests(space.region, space.space_id)
    return get_store().list_pentests(space.space_id)


# ---- Endpoints (target domains) ----
def list_endpoints(space: Space) -> list[VerifiedEndpoint]:
    if _sa():
        from . import securityagent
        return securityagent.list_endpoints_for_space(space)
    return space.endpoints


def create_endpoint(space: Space, url: str, verification_method: str = "DNS_TXT") -> VerifiedEndpoint:
    if _sa():
        from . import securityagent
        endpoint = securityagent.create_target_domain(space.region, url, verification_method)
        if endpoint.id and endpoint.id not in space.target_domain_ids:
            space.target_domain_ids.append(endpoint.id)
        return endpoint
    # memory
    endpoint = VerifiedEndpoint(url=url)
    space.endpoints.append(endpoint)
    get_store().upsert_space(space)
    return endpoint


def create_standalone_endpoint(region: str, url: str, verification_method: str = "DNS_TXT") -> VerifiedEndpoint:
    """Cria um alvo sem Space associado (ex.: no modal de criação de Space,
    antes de o Space existir). No modo securityagent vira um target domain de
    verdade, com id — associável depois via CreateSpaceRequest.target_domain_ids.
    No modo memory não há onde persistir; a URL só é anexada quando o Space
    for criado, via CreateSpaceRequest.endpoints.
    """
    if _sa():
        from . import securityagent
        return securityagent.create_target_domain(region, url, verification_method)
    return VerifiedEndpoint(url=url)

"""Backend de desenvolvimento: o domínio Security Agent em memória.

Espelha `backends.real` função por função, com as mesmas assinaturas. O estado
vive no `MockState` de `mock.py`, carregado de `mock_data.json` e perdido no
restart.

Só existe porque o moto não cobre o serviço `securityagent`. EC2, IAM, S3 e
Secrets Manager não têm versão aqui: as funções de `aws.py` são chamadas
diretamente e o moto responde por baixo (ver `mock_aws.py`).
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

import httpx

# Estas são as funções reais: em dev quem responde é o moto.
from ..aws import _client, list_resources, store_credential, validate_role_arn_account
from ..config import get_settings
from ..errors import ApiError
from ..mock import get_mock
from ..schemas import (
    CreateSpaceRequest,
    CredentialRef,
    Pentest,
    PentestCreate,
    PentestStatus,
    PentestUpdate,
    PresignUploadResponse,
    Space,
    UpdateSpaceRequest,
    VerifiedEndpoint,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---- Spaces ----
def list_spaces(account_id: str, region: str) -> list[Space]:
    return get_mock().list_spaces(account_id, region)


def get_space(space_id: str) -> Space:
    sp = get_mock().get_space(space_id)
    if not sp:
        raise ApiError(404, f"Space '{space_id}' não encontrado")
    return sp


def create_space(account_id: str, region: str, body: CreateSpaceRequest) -> Space:
    sp = Space(space_id=f"as-{uuid4().hex[:8]}", name=body.name, description=body.description,
               account_id=account_id, region=region,
               endpoints=[VerifiedEndpoint(url=u) for u in body.endpoints],
               target_domain_ids=list(body.target_domain_ids),
               aws_resources=body.aws_resources, tags=dict(body.tags))
    return get_mock().upsert_space(sp)


def _merge_endpoints(current: list[VerifiedEndpoint], urls: list[str]) -> list[VerifiedEndpoint]:
    """Aplica a nova lista de URLs preservando o status já verificado das antigas."""
    by_url = {e.url: e for e in current}
    return [by_url.get(u) or VerifiedEndpoint(url=u) for u in urls]


def update_space(space_id: str, body: UpdateSpaceRequest) -> Space:
    """Edição parcial: só os campos presentes no corpo do PATCH são aplicados."""
    sent = body.model_fields_set
    space = get_space(space_id)
    data: dict = {}
    for name in ("name", "description", "aws_resources", "target_domain_ids", "tags"):
        if name in sent:
            data[name] = getattr(body, name)
    if "endpoints" in sent:
        data["endpoints"] = _merge_endpoints(space.endpoints, body.endpoints or [])
    return get_mock().upsert_space(space.model_copy(update=data))


def _purge_artifacts(region: str, space_id: str) -> int:
    """Apaga os artefatos do Space no S3 (do moto, em dev)."""
    objs = list_resources(region, space_id)
    if objs:
        _client("s3", region).delete_objects(
            Bucket=get_settings().s3_artifacts_bucket,
            Delete={"Objects": [{"Key": o.key} for o in objs]},
        )
    return len(objs)


def delete_space(space_id: str) -> dict:
    """Apaga o Space e o que depende dele: pentests (memória) e artefatos (S3)."""
    space = get_space(space_id)
    artifacts = _purge_artifacts(space.region, space_id)
    removed = get_mock().delete_space(space_id)
    removed["artifacts"] = artifacts
    return removed


# ---- Pentests ----
def list_pentests(space: Space) -> list[Pentest]:
    return get_mock().list_pentests(space.space_id)


def get_pentest(pentest_id: str) -> Pentest:
    pentest = get_mock().get_pentest(pentest_id)
    if not pentest:
        raise ApiError(404, f"Pentest '{pentest_id}' não encontrado")
    return pentest


def _validate_targets(space: Space, endpoints: list[str]) -> None:
    """Allowlist local: o alvo tem que estar registrado no Space.

    (No backend real quem valida é o próprio serviço.)
    """
    if not endpoints or not space.endpoints:
        return
    allowed = {e.url for e in space.endpoints}
    invalid = [e for e in endpoints if e not in allowed]
    if invalid:
        raise ApiError(403, f"Endpoint(s) alvo não registrados neste Space: {', '.join(invalid)}")


def _persist_credentials(region, space_id, pentest_id, creds) -> list[CredentialRef]:
    refs = []
    for c in creds:
        secret_arn = None
        if c.mode == "advanced" and c.secret_arn:
            secret_arn = c.secret_arn
        elif c.password or c.totp_secret:
            secret_arn = store_credential(region, space_id, pentest_id, c.actor_identifier,
                {"username": c.username, "password": c.password, "totp_secret": c.totp_secret})
        refs.append(CredentialRef(actor_identifier=c.actor_identifier, secret_arn=secret_arn,
                                  access_url=c.access_url, has_2fa=bool(c.totp_secret)))
    return refs


def create_pentest(space: Space, body: PentestCreate) -> Pentest:
    validate_role_arn_account(space.account_id, body.target.service_role_arn)
    _validate_targets(space, body.target.endpoints)
    pentest_id = f"pt-{uuid4().hex[:12]}"
    refs = _persist_credentials(space.region, space.space_id, pentest_id, body.credentials)
    now = _now()
    pentest = Pentest(id=pentest_id, space_id=space.space_id, title=body.title,
        status=PentestStatus.PENDING, network=body.network, target=body.target,
        credentials=refs, resources=body.resources, created_at=now, updated_at=now)
    return get_mock().put_pentest(pentest)


def start_pentest(pentest_id: str, space_id: str | None) -> dict:
    """Não há job real: simula a conclusão imediata e devolve o pentest inteiro."""
    pentest = get_pentest(pentest_id)
    updated = pentest.model_copy(update={"status": PentestStatus.COMPLETED, "updated_at": _now()})
    return get_mock().put_pentest(updated).model_dump(mode="json")


def update_pentest(pentest_id: str, body: PentestUpdate) -> Pentest:
    pentest = get_pentest(pentest_id)
    if body.target is not None:
        space = get_space(pentest.space_id)
        _validate_targets(space, body.target.endpoints)
        validate_role_arn_account(space.account_id, body.target.service_role_arn)
    data = {f: getattr(body, f) for f in body.model_fields_set if f != "space_id"}
    updated = pentest.model_copy(update={**data, "updated_at": _now()})
    return get_mock().put_pentest(updated)


def delete_pentest(pentest_id: str) -> dict:
    removed = get_mock().delete_pentest(pentest_id)
    if not removed:
        raise ApiError(404, f"Pentest '{pentest_id}' não encontrado")
    return removed


# ---- Endpoints (target domains) ----
def list_endpoints(space: Space) -> list[VerifiedEndpoint]:
    return space.endpoints


def create_endpoint(space: Space, url: str, verification_method: str = "DNS_TXT") -> VerifiedEndpoint:
    endpoint = VerifiedEndpoint(url=url)
    space.endpoints.append(endpoint)
    get_mock().upsert_space(space)
    return endpoint


def create_standalone_endpoint(region: str, url: str, verification_method: str = "DNS_TXT") -> VerifiedEndpoint:
    """Sem Space não há onde persistir; a URL só é anexada quando o Space for
    criado, via CreateSpaceRequest.endpoints."""
    return VerifiedEndpoint(url=url)


def verify_endpoint(space: Space, url: str, target_domain_id: str | None = None) -> VerifiedEndpoint:
    """Allowlist + checagem HTTP leve (não há target domain para verificar)."""
    endpoint = next((e for e in space.endpoints if e.url == url), None)
    if endpoint is None:
        raise ApiError(403, "Endpoint não registrado neste Space (escopo autorizado).")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        endpoint.status = "FAILED"; endpoint.detail = "URL inválida"
        get_mock().upsert_space(space)
        return endpoint
    endpoint.status = "VERIFYING"
    try:
        resp = httpx.head(url, timeout=5.0, follow_redirects=True)
        endpoint.status = "VERIFIED" if resp.status_code < 500 else "FAILED"
        endpoint.detail = f"HTTP {resp.status_code}"
    except httpx.HTTPError as exc:
        endpoint.status = "FAILED"; endpoint.detail = f"Sem resposta: {exc.__class__.__name__}"
    endpoint.verified_at = _now()
    get_mock().upsert_space(space)
    return endpoint


# ---- S3 ----
def presign_upload(
    region: str, account_id: str, space_id: str, filename: str, content_type: str | None
) -> PresignUploadResponse:
    """URL de upload apontando para a própria app: um presigned do moto iria
    para `s3.amazonaws.com`, que o browser não alcança."""
    return get_mock().presign_upload(space_id, filename, content_type)

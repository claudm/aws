"""Fachada única de dados para as rotas.

Só repassa a chamada para o backend ativo (`backends.real` ou
`backends.memory`), que expõem as mesmas funções com as mesmas assinaturas.
Não há decisão de modo aqui: em dev chama-se a mesma função, só que a do mock.

Cobre apenas o que precisa de duas versões: o domínio do serviço
`securityagent` e o presign de upload. EC2, IAM, S3 e Secrets Manager têm
implementação única e as rotas os chamam direto de `aws.py`.
"""
from __future__ import annotations

from .backends import get_backend
from .schemas import (
    CreateSpaceRequest,
    Pentest,
    PentestCreate,
    PentestUpdate,
    PresignUploadResponse,
    Space,
    UpdateSpaceRequest,
    VerifiedEndpoint,
)


# ---- Spaces ----
def list_spaces(account_id: str, region: str) -> list[Space]:
    return get_backend().list_spaces(account_id, region)


def get_space(space_id: str) -> Space:
    return get_backend().get_space(space_id)


def create_space(account_id: str, region: str, body: CreateSpaceRequest) -> Space:
    return get_backend().create_space(account_id, region, body)


def update_space(space_id: str, body: UpdateSpaceRequest) -> Space:
    return get_backend().update_space(space_id, body)


def delete_space(space_id: str) -> dict:
    return get_backend().delete_space(space_id)


# ---- Pentests ----
def list_pentests(space: Space) -> list[Pentest]:
    return get_backend().list_pentests(space)


def get_pentest(pentest_id: str) -> Pentest:
    return get_backend().get_pentest(pentest_id)


def create_pentest(space: Space, body: PentestCreate) -> Pentest:
    return get_backend().create_pentest(space, body)


def start_pentest(pentest_id: str, space_id: str | None) -> dict:
    """Devolve o corpo da resposta já pronto: os dois backends informam coisas
    diferentes (status do job no real, pentest inteiro no memory)."""
    return get_backend().start_pentest(pentest_id, space_id)


def update_pentest(pentest_id: str, body: PentestUpdate) -> Pentest:
    return get_backend().update_pentest(pentest_id, body)


def delete_pentest(pentest_id: str) -> dict:
    return get_backend().delete_pentest(pentest_id)


# ---- Endpoints (target domains) ----
def list_endpoints(space: Space) -> list[VerifiedEndpoint]:
    return get_backend().list_endpoints(space)


def create_endpoint(space: Space, url: str, verification_method: str = "DNS_TXT") -> VerifiedEndpoint:
    return get_backend().create_endpoint(space, url, verification_method)


def create_standalone_endpoint(region: str, url: str, verification_method: str = "DNS_TXT") -> VerifiedEndpoint:
    """Alvo criado antes de o Space existir (ex.: modal "Criar Agent Space")."""
    return get_backend().create_standalone_endpoint(region, url, verification_method)


def verify_endpoint(space: Space, url: str, target_domain_id: str | None = None) -> VerifiedEndpoint:
    return get_backend().verify_endpoint(space, url, target_domain_id)


# ---- S3 ----
def presign_upload(
    region: str, account_id: str, space_id: str, filename: str, content_type: str | None
) -> PresignUploadResponse:
    """Difere por ambiente: presigned do S3 em produção, rota local em dev."""
    return get_backend().presign_upload(region, account_id, space_id, filename, content_type)

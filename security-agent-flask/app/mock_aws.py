"""Mock de recursos AWS (EC2/IAM/S3/Secrets Manager) para o ambiente de dev.

Usado no lugar de boto3/kumo quando SA_BACKEND=memory, para que VPCs, Subnets,
Security Groups, Roles, artefatos do S3 e credenciais funcionem offline. Os
dados vêm de `mock_data.json` (ver mock_data.py) e ficam só na memória do
processo: nada é gravado na AWS. Spaces e Pentests têm o mock equivalente em
mock_store.MockStore.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from urllib.parse import quote
from uuid import uuid4

from .config import get_settings
from .mock_data import load_mock_data
from .schemas import (
    PresignUploadResponse,
    ResourceObject,
    RoleOut,
    SecurityGroupOut,
    SubnetOut,
    VpcOut,
)


class MockAwsClient:
    """Dados fake de EC2/IAM/S3, fixos por processo, para dev sem AWS/kumo."""

    def __init__(self) -> None:
        settings = get_settings()
        self._account_id = settings.expected_account_id or "000000000000"
        self._bucket = settings.s3_artifacts_bucket
        self._prefix = settings.s3_artifacts_prefix
        self._secrets_prefix = settings.secrets_prefix

        data = load_mock_data()
        self._vpcs = [VpcOut(**v) for v in data.get("vpcs", [])]
        self._subnets = [SubnetOut(**s) for s in data.get("subnets", [])]
        self._security_groups = [SecurityGroupOut(**sg) for sg in data.get("security_groups", [])]
        self._roles = [RoleOut(**r) for r in data.get("roles", [])]
        # space_id -> artefatos "no S3"; uploads do modo mock entram aqui.
        self._resources: dict[str, list[ResourceObject]] = {}
        for r in data.get("resources", []):
            obj = self._resource(r["space_id"], r["name"], r["size"], r.get("last_modified"))
            self._resources.setdefault(r["space_id"], []).append(obj)

    # ---- EC2 ----
    def list_vpcs(self, q: str | None = None) -> list[VpcOut]:
        return [v for v in self._vpcs if _matches(q, v.vpc_id, v.name)]

    def list_subnets(self, vpc_id: str) -> list[SubnetOut]:
        return [s for s in self._subnets if s.vpc_id == vpc_id]

    def list_security_groups(self, vpc_id: str | None = None, q: str | None = None) -> list[SecurityGroupOut]:
        out = self._security_groups
        if vpc_id:
            out = [sg for sg in out if sg.vpc_id == vpc_id]
        return [sg for sg in out if _matches(q, sg.group_id, sg.name)]

    # ---- IAM ----
    def list_roles(self, q: str | None = None) -> list[RoleOut]:
        return [r for r in self._roles if _matches(q, r.arn, r.role_name)]

    # ---- Secrets Manager ----
    def store_credential(self, region: str, space_id: str, pentest_id: str, actor_identifier: str) -> str:
        """ARN fake: a credencial não sai do request (nada é gravado)."""
        safe_actor = actor_identifier.replace("/", "_").replace(" ", "-")
        name = f"{self._secrets_prefix}/{space_id}/{pentest_id}/{safe_actor}"
        return f"arn:aws:secretsmanager:{region}:{self._account_id}:secret:{name}-mock"

    # ---- S3 ----
    def list_resources(self, space_id: str) -> list[ResourceObject]:
        return list(self._resources.get(space_id, []))

    def presign_upload(
        self, space_id: str, filename: str, content_type: str | None
    ) -> PresignUploadResponse:
        """URL de upload apontando para a própria app (rota mock), em vez do S3."""
        key = self._key(space_id, filename)
        url = f"/api/resources/mock-upload?space_id={quote(space_id)}&key={quote(key)}"
        return PresignUploadResponse(
            url=url, content_type=content_type, key=key, s3_uri=f"s3://{self._bucket}/{key}"
        )

    def register_upload(self, space_id: str, key: str, size: int) -> ResourceObject:
        """Registra em memória o arquivo 'enviado' para a URL mock."""
        obj = ResourceObject(
            name=key.rsplit("/", 1)[-1], key=key, s3_uri=f"s3://{self._bucket}/{key}",
            size=size, last_modified=datetime.now(timezone.utc),
        )
        self._resources.setdefault(space_id, []).append(obj)
        return obj

    def _key(self, space_id: str, filename: str) -> str:
        return (
            f"{self._prefix}/{self._account_id}/{space_id}/"
            f"{date.today().isoformat()}/{uuid4()}/{filename}"
        )

    def _resource(self, space_id: str, name: str, size: int, last_modified: str | None) -> ResourceObject:
        key = f"{self._prefix}/{self._account_id}/{space_id}/{name}"
        return ResourceObject(
            name=name, key=key, s3_uri=f"s3://{self._bucket}/{key}",
            size=size, last_modified=last_modified,
        )


def _matches(q: str | None, *fields: str | None) -> bool:
    if not q:
        return True
    needle = q.lower()
    return any(needle in (f or "").lower() for f in fields)


_client: MockAwsClient | None = None


def get_mock_aws_client() -> MockAwsClient:
    global _client
    if _client is None:
        _client = MockAwsClient()
    return _client

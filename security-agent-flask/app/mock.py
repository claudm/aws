"""Estado em memória do modo dev: Spaces, Pentests e a URL de upload local.

O JSON é lido uma vez por processo e **nunca é reescrito**: criação, atualização
e remoção valem só na memória e somem no restart.

EC2, IAM, S3 e Secrets Manager **não estão aqui**: em dev quem responde por eles
é o moto (ver `mock_aws.py`), contra o qual as funções reais de `aws.py` rodam
sem alteração. Este módulo cobre só o que o moto não sabe fazer — o domínio do
serviço `securityagent` — e o presign, que precisa apontar para a própria app.

Strings do JSON aceitam placeholders resolvidos a partir das settings:
`{account_id}`, `{region}`, `{bucket}` e `{prefix}`.
"""
from __future__ import annotations

import json
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from .config import get_settings
from .schemas import Pentest, PresignUploadResponse, Space

MOCK_DATA_FILE = Path(__file__).with_name("mock_data.json")


def is_mock() -> bool:
    """Gate único do modo mock (antes duplicado em `aws._mock`)."""
    return get_settings().sa_backend == "memory"


@lru_cache
def load_raw_mock_data() -> dict[str, list[dict]]:
    """JSON com os placeholders resolvidos, ainda com os ids de VPC/subnet/SG
    do arquivo. É desta forma que `mock_aws` semeia o moto."""
    settings = get_settings()
    ctx = {
        "account_id": settings.expected_account_id or "000000000000",
        "region": settings.aws_region,
        "bucket": settings.s3_artifacts_bucket,
        "prefix": settings.s3_artifacts_prefix,
    }
    raw = json.loads(MOCK_DATA_FILE.read_text(encoding="utf-8"))
    return _render(raw, ctx)


@lru_cache
def load_mock_data() -> dict[str, list[dict]]:
    """Como `load_raw_mock_data`, mas com os ids de rede trocados pelos que o
    moto gerou — é o que os Spaces e Pentests referenciam."""
    from .mock_aws import start

    return _remap(load_raw_mock_data(), start())


def _render(value: Any, ctx: dict[str, str]) -> Any:
    """Aplica os placeholders recursivamente em todas as strings do JSON."""
    if isinstance(value, str):
        return value.format(**ctx)
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, ctx) for k, v in value.items()}
    return value


def _remap(value: Any, ids: dict[str, str]) -> Any:
    """Troca os ids de rede do arquivo pelos do moto, em qualquer string."""
    if isinstance(value, str):
        for old, new in ids.items():
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [_remap(v, ids) for v in value]
    if isinstance(value, dict):
        return {k: _remap(v, ids) for k, v in value.items()}
    return value


class MockState:
    """Spaces e Pentests do processo — o que `backends.memory` serve."""

    def __init__(self) -> None:
        settings = get_settings()
        self._account_id = settings.expected_account_id or "000000000000"
        self._bucket = settings.s3_artifacts_bucket
        self._prefix = settings.s3_artifacts_prefix

        data = load_mock_data()
        self._spaces: dict[str, Space] = {
            s["space_id"]: Space(**s) for s in data.get("spaces", [])
        }
        self._pentests: dict[str, Pentest] = {
            p["id"]: Pentest(**p) for p in data.get("pentests", [])
        }

    # ---- Spaces ----
    def upsert_space(self, space: Space) -> Space:
        self._spaces[space.space_id] = space
        return space

    def get_space(self, space_id: str) -> Space | None:
        return self._spaces.get(space_id)

    def list_spaces(self, account_id: str, region: str) -> list[Space]:
        return [
            s for s in self._spaces.values()
            if s.account_id == account_id and s.region == region
        ]

    def delete_space(self, space_id: str) -> dict[str, int | str] | None:
        """Remove o Space e seus pentests. Os artefatos vivem no S3 (moto) e
        são apagados por `backends.memory.delete_space`."""
        if space_id not in self._spaces:
            return None
        pentest_ids = [p.id for p in self._pentests.values() if p.space_id == space_id]
        for pid in pentest_ids:
            del self._pentests[pid]
        del self._spaces[space_id]
        return {"space_id": space_id, "pentests": len(pentest_ids)}

    # ---- Pentests ----
    def put_pentest(self, pentest: Pentest) -> Pentest:
        self._pentests[pentest.id] = pentest
        return pentest

    def get_pentest(self, pentest_id: str) -> Pentest | None:
        return self._pentests.get(pentest_id)

    def list_pentests(self, space_id: str) -> list[Pentest]:
        items = [p for p in self._pentests.values() if p.space_id == space_id]
        return sorted(items, key=lambda p: p.created_at, reverse=True)

    def delete_pentest(self, pentest_id: str) -> dict[str, str] | None:
        pentest = self._pentests.pop(pentest_id, None)
        if pentest is None:
            return None
        return {"pentest_id": pentest_id, "space_id": pentest.space_id}

    # ---- S3 ----
    def presign_upload(
        self, space_id: str, filename: str, content_type: str | None
    ) -> PresignUploadResponse:
        """URL de upload apontando para a própria app, em vez do S3.

        Um presigned do moto apontaria para `s3.amazonaws.com`, que o browser
        não alcança — é o único ponto do fluxo de artefatos que o moto não
        cobre. O PUT nessa rota grava o objeto no S3 do moto, e a listagem
        depois vem de lá.
        """
        key = self.artifact_key(space_id, filename)
        url = f"/api/resources/mock-upload?space_id={quote(space_id)}&key={quote(key)}"
        return PresignUploadResponse(
            url=url, content_type=content_type, key=key, s3_uri=f"s3://{self._bucket}/{key}"
        )

    def artifact_key(self, space_id: str, filename: str) -> str:
        return (
            f"{self._prefix}/{self._account_id}/{space_id}/"
            f"{date.today().isoformat()}/{uuid4()}/{filename}"
        )


_state: MockState | None = None


def get_mock() -> MockState:
    global _state
    if _state is None:
        _state = MockState()
    return _state

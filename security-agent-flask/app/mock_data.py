"""Carrega as fixtures JSON dos mocks (rede, IAM, Spaces, Pentests, artefatos).

Fonte única dos dados fake: `app/mock_data.json`. O arquivo é lido uma vez por
processo e servido em memória — nenhum mock grava em DynamoDB, S3, Secrets
Manager ou qualquer outro serviço AWS.

Strings do JSON aceitam placeholders resolvidos a partir das settings:
`{account_id}`, `{region}`, `{bucket}` e `{prefix}`.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .config import get_settings

MOCK_DATA_FILE = Path(__file__).with_name("mock_data.json")


@lru_cache
def load_mock_data() -> dict[str, list[dict]]:
    settings = get_settings()
    ctx = {
        "account_id": settings.expected_account_id or "000000000000",
        "region": settings.aws_region,
        "bucket": settings.s3_artifacts_bucket,
        "prefix": settings.s3_artifacts_prefix,
    }
    raw = json.loads(MOCK_DATA_FILE.read_text(encoding="utf-8"))
    return _render(raw, ctx)


def _render(value: Any, ctx: dict[str, str]) -> Any:
    """Aplica os placeholders recursivamente em todas as strings do JSON."""
    if isinstance(value, str):
        return value.format(**ctx)
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, ctx) for k, v in value.items()}
    return value

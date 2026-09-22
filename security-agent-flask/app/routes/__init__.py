"""Rotas de API (JSON), todas sob `/api`.

Um blueprint só (`bp`), com um módulo por entidade: `context` (Spaces),
`network`, `targets`, `pentests` e `resources` — cada um com as leituras e as
escritas (POST/PATCH/DELETE) da sua entidade. As rotas que renderizam template
ficam em `app/views/`.
"""
from flask import Blueprint, jsonify, request

from ..config import get_settings

bp = Blueprint("api", __name__, url_prefix="/api")


def _region() -> str:
    """Região da querystring, com fallback para AWS_REGION."""
    return request.args.get("region") or get_settings().aws_region


@bp.get("/health")
def health():
    settings = get_settings()
    return jsonify(
        {
            "status": "ok",
            "sa_backend": settings.sa_backend,
            "region": settings.aws_region,
        }
    )


# Importados no fim para registrar as rotas no `bp` definido acima.
from . import context, llm, network, pentests, resources, targets  # noqa: E402,F401

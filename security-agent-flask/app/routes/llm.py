"""LLM do design review: qual backend/modelo o Security Agent usa.

Proxy fino para as rotas /_kumo/* do kumo. Elas nao sao API AWS, entao ficam
fora do boto3 e do backend memory/real -- e por isso tambem nao existem quando
a tela roda sem um kumo na frente, caso em que a secao aparece desabilitada em
vez de quebrar a pagina.
"""
from __future__ import annotations

import httpx
from flask import jsonify, request

from ..config import get_settings
from . import bp

TIMEOUT = 20.0


def _kumo_base_or_error():
    base = get_settings().kumo_base
    if not base:
        return None, (jsonify({"detail": "kumo nao configurado (defina KUMO_ENDPOINT ou AWS_ENDPOINT_URL)"}), 503)
    return base, None


def _forward(method: str, path: str, json_body=None):
    base, err = _kumo_base_or_error()
    if err:
        return err
    try:
        res = httpx.request(method, f"{base}{path}", json=json_body, timeout=TIMEOUT)
    except httpx.HTTPError as exc:
        return jsonify({"detail": f"kumo inacessivel: {exc}"}), 502

    try:
        data = res.json()
    except ValueError:
        return jsonify({"detail": f"resposta nao-JSON do kumo (HTTP {res.status_code})"}), 502

    # O kumo responde erro como {"error": "..."}; a tela espera {"detail": ...}.
    if res.status_code >= 400:
        return jsonify({"detail": data.get("error") or f"HTTP {res.status_code}"}), res.status_code
    return jsonify(data)


@bp.get("/llm/design-review")
def get_design_review_llm():
    return _forward("GET", "/_kumo/securityagent/llm")


@bp.put("/llm/design-review")
def put_design_review_llm():
    body = request.get_json(silent=True) or {}
    return _forward("PUT", "/_kumo/securityagent/llm", {
        "backend": (body.get("backend") or "").strip(),
        "model": (body.get("model") or "").strip(),
    })


@bp.get("/llm/models")
def get_llm_models():
    """Modelos de um backend, na forma {models:[{name}]} que o kumo ja devolve."""
    backend = (request.args.get("backend") or "").strip()
    if not backend:
        return jsonify({"detail": "backend e obrigatorio"}), 400
    return _forward("GET", f"/_kumo/llm/{backend}/tags")

"""Alvo e permissão: endpoints (target domains) e role de serviço."""
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from flask import Blueprint, jsonify, request

from ..aws import list_roles
from ..config import get_settings
from ..errors import ApiError
from ..providers import create_endpoint, create_standalone_endpoint, get_space, list_endpoints
from ..schemas import CreateEndpointRequest, VerifyEndpointRequest
from ..store import get_store
from ..validation import dump, dump_list, parse_body

bp = Blueprint("targets", __name__, url_prefix="/api/targets")


@bp.get("/endpoints")
def list_endpoints_route():
    space_id = request.args.get("space_id")
    if not space_id:
        raise ApiError(400, "Parâmetro 'space_id' é obrigatório")
    return jsonify(dump_list(list_endpoints(get_space(space_id))))


@bp.post("/endpoints")
def create_endpoint_route():
    body = parse_body(CreateEndpointRequest)
    if body.space_id:
        space = get_space(body.space_id)
        return jsonify(dump(create_endpoint(space, body.url, body.verification_method))), 201
    # sem space_id: alvo criado antes de o Space existir (ex.: modal "Criar Agent Space")
    region = body.region or get_settings().aws_region
    return jsonify(dump(create_standalone_endpoint(region, body.url, body.verification_method))), 201


@bp.post("/endpoints/verify")
def verify_endpoint():
    body = parse_body(VerifyEndpointRequest)
    space = get_space(body.space_id)
    settings = get_settings()

    # Modo securityagent: verifica o target domain de verdade.
    if settings.sa_backend == "securityagent":
        from .. import securityagent
        tid = body.target_domain_id or securityagent.resolve_target_domain(space.region, body.url)
        if not tid:
            raise ApiError(404, "Target domain não encontrado para este endpoint.")
        return jsonify(dump(securityagent.verify_target_domain(space.region, tid)))

    # Modo memory: allowlist + checagem HTTP leve.
    endpoint = next((e for e in space.endpoints if e.url == body.url), None)
    if endpoint is None:
        raise ApiError(403, "Endpoint não registrado neste Space (escopo autorizado).")
    parsed = urlparse(body.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        endpoint.status = "FAILED"; endpoint.detail = "URL inválida"
        get_store().upsert_space(space); return jsonify(dump(endpoint))
    endpoint.status = "VERIFYING"
    try:
        resp = httpx.head(body.url, timeout=5.0, follow_redirects=True)
        endpoint.status = "VERIFIED" if resp.status_code < 500 else "FAILED"
        endpoint.detail = f"HTTP {resp.status_code}"
    except httpx.HTTPError as exc:
        endpoint.status = "FAILED"; endpoint.detail = f"Sem resposta: {exc.__class__.__name__}"
    endpoint.verified_at = datetime.now(timezone.utc)
    get_store().upsert_space(space)
    return jsonify(dump(endpoint))


@bp.get("/roles")
def get_roles():
    region = request.args.get("region") or get_settings().aws_region
    return jsonify(dump_list(list_roles(region, request.args.get("q"))))

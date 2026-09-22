"""Alvo e permissão: endpoints (target domains) e role de serviço."""
from flask import jsonify, request

from ..aws import list_roles
from ..config import get_settings
from ..errors import ApiError
from ..providers import (
    create_endpoint,
    create_standalone_endpoint,
    get_space,
    list_endpoints,
    verify_endpoint as verify,
)
from ..schemas import CreateEndpointRequest, VerifyEndpointRequest
from ..validation import dump, dump_list, parse_body
from . import _region, bp


@bp.get("/targets/endpoints")
def list_endpoints_route():
    space_id = request.args.get("space_id")
    if not space_id:
        raise ApiError(400, "Parâmetro 'space_id' é obrigatório")
    return jsonify(dump_list(list_endpoints(get_space(space_id))))


@bp.post("/targets/endpoints")
def create_endpoint_route():
    body = parse_body(CreateEndpointRequest)
    if body.space_id:
        space = get_space(body.space_id)
        return jsonify(dump(create_endpoint(space, body.url, body.verification_method))), 201
    # sem space_id: alvo criado antes de o Space existir (ex.: modal "Criar Agent Space")
    region = body.region or get_settings().aws_region
    return jsonify(dump(create_standalone_endpoint(region, body.url, body.verification_method))), 201


@bp.post("/targets/endpoints/verify")
def verify_endpoint():
    body = parse_body(VerifyEndpointRequest)
    space = get_space(body.space_id)
    return jsonify(dump(verify(space, body.url, body.target_domain_id)))


@bp.get("/targets/roles")
def get_roles():
    return jsonify(dump_list(list_roles(_region(), request.args.get("q"))))

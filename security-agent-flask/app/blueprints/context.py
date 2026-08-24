"""Contexto AWS + Spaces do Security Agent."""
from flask import Blueprint, jsonify

from ..aws import validate_role_arn_account
from ..config import get_settings
from ..providers import create_space, get_space, list_spaces, update_space
from ..schemas import CreateSpaceRequest, LoadContextRequest, UpdateSpaceRequest
from ..validation import dump, dump_list, parse_body

bp = Blueprint("context", __name__, url_prefix="/api/context")


@bp.post("/spaces")
def load_spaces():
    body = parse_body(LoadContextRequest)
    settings = get_settings()
    if settings.sa_backend == "securityagent":
        from ..aws import assume_cross_account
        assume_cross_account(body.account_id, body.region)
    return jsonify(dump_list(list_spaces(body.account_id, body.region)))


@bp.get("/spaces/<space_id>")
def get_space_route(space_id: str):
    return jsonify(dump(get_space(space_id)))


@bp.post("/spaces/create")
def create_space_route():
    body = parse_body(CreateSpaceRequest)
    settings = get_settings()
    account = settings.expected_account_id or ""
    region = settings.aws_region
    for role_arn in (body.aws_resources or {}).get("iamRoles", []) or []:
        validate_role_arn_account(account, role_arn)
    return jsonify(dump(create_space(account, region, body))), 201


@bp.patch("/spaces/<space_id>")
def update_space_route(space_id: str):
    body = parse_body(UpdateSpaceRequest)
    settings = get_settings()
    account = settings.expected_account_id or ""
    for role_arn in (body.aws_resources or {}).get("iamRoles", []) or []:
        validate_role_arn_account(account, role_arn)
    return jsonify(dump(update_space(space_id, body)))

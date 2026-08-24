from flask import Blueprint, jsonify, request

from ..aws import list_security_groups, list_subnets, list_vpcs
from ..config import get_settings
from ..validation import dump_list

bp = Blueprint("network", __name__, url_prefix="/api/network")


def _region() -> str:
    return request.args.get("region") or get_settings().aws_region


@bp.get("/vpcs")
def get_vpcs():
    return jsonify(dump_list(list_vpcs(_region(), request.args.get("q"))))


@bp.get("/vpcs/<vpc_id>/subnets")
def get_subnets(vpc_id: str):
    return jsonify(dump_list(list_subnets(_region(), vpc_id)))


@bp.get("/security-groups")
def get_security_groups():
    return jsonify(
        dump_list(
            list_security_groups(_region(), request.args.get("vpc_id"), request.args.get("q"))
        )
    )

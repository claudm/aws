"""Rede (EC2): VPCs, subnets e security groups."""
from flask import jsonify, request

from ..aws import list_security_groups, list_subnets, list_vpcs
from ..validation import dump_list
from . import _region, bp


@bp.get("/network/vpcs")
def get_vpcs():
    return jsonify(dump_list(list_vpcs(_region(), request.args.get("q"))))


@bp.get("/network/vpcs/<vpc_id>/subnets")
def get_subnets(vpc_id: str):
    return jsonify(dump_list(list_subnets(_region(), vpc_id)))


@bp.get("/network/security-groups")
def get_security_groups():
    return jsonify(
        dump_list(
            list_security_groups(_region(), request.args.get("vpc_id"), request.args.get("q"))
        )
    )

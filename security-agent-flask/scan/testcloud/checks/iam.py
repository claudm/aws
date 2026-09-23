"""Checks de identidade (IAM). Escopo global — rodam uma única vez."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

def users(ctx: ScanContext):
    return ctx.cached("iam:users", lambda: ctx.paginate("iam", "list_users", "Users"))


@resource_provider("iam", "root")
def iter_root(ctx: ScanContext):
    yield {
        "resource_id": f"root:{ctx.account_id}",
        "region": "global",
        "arn": f"arn:{ctx.partition}:iam::{ctx.account_id}:root",
        "params": {},
    }


@resource_provider("iam", "password_policy")
def iter_password_policy(ctx: ScanContext):
    yield {
        "resource_id": f"password-policy:{ctx.account_id}",
        "region": "global",
        "params": {},
    }


@resource_provider("iam", "user")
def iter_users(ctx: ScanContext):
    for user in users(ctx):
        yield {
            "resource_id": user["UserName"],
            "region": "global",
            "arn": user["Arn"],
            "params": {"UserName": user["UserName"]},
            "vars": [user["UserName"]],
        }


@resource_provider("iam", "access_key")
def iter_access_keys(ctx: ScanContext):
    for user in users(ctx):
        name = user["UserName"]
        for key in ctx.paginate("iam", "list_access_keys", "AccessKeyMetadata", UserName=name):
            yield {
                "resource_id": f"{name}#{key['AccessKeyId']}",
                "region": "global",
                "arn": user["Arn"],
                "params": {"UserName": name, "AccessKeyId": key["AccessKeyId"]},
                "vars": [key["AccessKeyId"], name],
            }


@resource_provider("iam", "policy")
def iter_local_policies(ctx: ScanContext):
    for pol in ctx.paginate("iam", "list_policies", "Policies", Scope="Local", OnlyAttached=True):
        yield {
            "resource_id": pol["PolicyName"],
            "region": "global",
            "arn": pol["Arn"],
            "params": {"PolicyArn": pol["Arn"], "VersionId": pol["DefaultVersionId"]},
            "vars": [pol["PolicyName"]],
        }

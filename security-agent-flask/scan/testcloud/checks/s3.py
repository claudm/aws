"""Checks de S3. Escopo global: a listagem de buckets é global, mas cada
operação de configuração é feita no endpoint regional correto do bucket."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from botocore.exceptions import ClientError

from ..context import ScanContext
from ..models import Pillar, Severity
from ..registry import check, resource_provider

PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

@resource_provider("s3", "bucket")
def iter_buckets(ctx: ScanContext) -> List[Dict[str, Any]]:
    """Lista buckets + região de cada um (cacheado por scan)."""

    def _load():
        s3 = ctx.client("s3", region="us-east-1")
        out = []
        for b in s3.list_buckets().get("Buckets", []):
            try:
                loc = s3.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint")
            except ClientError:
                loc = None
            out.append({
                "resource_id": b["Name"], 
                "region": loc or "us-east-1", 
                "params": {"Bucket": b["Name"]}
            })
        ctx.resources_seen += len(out)
        return out

    return ctx.cached("s3:buckets", _load)

def _buckets(ctx: ScanContext) -> List[Dict[str, Any]]:
    # backward compatibility for access_logging loop
    return [{"Name": b["resource_id"], "Region": b["region"]} for b in iter_buckets(ctx)]


def _bclient(ctx: ScanContext, bucket: Dict[str, Any]):
    return ctx.client("s3", region=bucket["Region"])


def _quiet(fn, *codes):
    """Executa e devolve None quando o erro é 'configuração ausente'."""
    try:
        return fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] in codes:
            return None
        raise


def _arn(ctx: ScanContext, name: str) -> str:
    return f"arn:{ctx.partition}:s3:::{name}"


@resource_provider("s3control", "account")
def iter_account(ctx: ScanContext):
    yield {
        "resource_id": f"s3-account-pab:{ctx.account_id}",
        "region": "us-east-1",
        "params": {"AccountId": ctx.account_id}
    }
"""Controles detectivos e de governança: CloudTrail, Config, GuardDuty,
IAM Access Analyzer, Security Hub, KMS e Secrets Manager."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("cloudtrail", "account")
def iter_cloudtrail_account(ctx: ScanContext):
    yield {"resource_id": f"cloudtrail:{ctx.account_id}", "region": "global", "params": {}}


@resource_provider("cloudtrail", "trail")
def iter_trails(ctx: ScanContext):
    resp = ctx.call("cloudtrail", "describe_trails", region="us-east-1", includeShadowTrails=True)
    seen = set()
    for t in (resp or {}).get("trailList", []):
        arn = t.get("TrailARN", "")
        if arn in seen:
            continue
        seen.add(arn)
        yield {
            "resource_id": t.get("Name", arn),
            "region": t.get("HomeRegion", "us-east-1"),
            "arn": arn,
            "params": {"Name": arn},
            "vars": [t.get("Name")],
        }


@resource_provider("guardduty", "region")
def iter_guardduty_region(ctx: ScanContext):
    yield {"resource_id": f"guardduty:{ctx.region}", "region": ctx.region, "params": {}}


@resource_provider("config", "region")
def iter_config_region(ctx: ScanContext):
    yield {"resource_id": f"config-recorder:{ctx.region}", "region": ctx.region, "params": {}}


@resource_provider("accessanalyzer", "region")
def iter_access_analyzer_region(ctx: ScanContext):
    yield {"resource_id": f"access-analyzer:{ctx.region}", "region": ctx.region, "params": {}}


@resource_provider("kms", "key")
def iter_keys(ctx: ScanContext):
    for key in ctx.paginate("kms", "list_keys", "Keys"):
        yield {
            "resource_id": key["KeyId"],
            "region": ctx.region,
            "arn": key.get("KeyArn", ""),
            "params": {"KeyId": key["KeyId"]},
            "vars": [key["KeyId"]],
        }


@resource_provider("secretsmanager", "secret")
def iter_secrets(ctx: ScanContext):
    for secret in ctx.paginate("secretsmanager", "list_secrets", "SecretList"):
        yield {
            "resource_id": secret["Name"],
            "region": ctx.region,
            "arn": secret["ARN"],
            "params": {"SecretId": secret["ARN"]},
            "vars": [secret["Name"]],
        }

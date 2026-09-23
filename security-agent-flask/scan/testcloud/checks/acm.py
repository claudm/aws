"""Checks de AWS Certificate Manager. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("acm", "certificate")
def iter_certificates(ctx: ScanContext):
    for cert in ctx.paginate("acm", "list_certificates", "CertificateSummaryList"):
        arn = cert["CertificateArn"]
        yield {
            "resource_id": arn.split("/")[-1],
            "region": ctx.region,
            "arn": arn,
            "params": {"CertificateArn": arn},
        }

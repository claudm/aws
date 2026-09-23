"""Checks de AWS Global Accelerator. Escopo global."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("globalaccelerator", "accelerator")
def iter_accelerators(ctx: ScanContext):
    # A API do Global Accelerator só responde em us-west-2.
    try:
        pages = ctx.client("globalaccelerator", region="us-west-2").get_paginator("list_accelerators").paginate()
        accels = [a for page in pages for a in page.get("Accelerators", [])]
    except Exception:
        return
    ctx.resources_seen += len(accels)
    for acc in accels:
        yield {
            "resource_id": acc.get("Name"),
            "region": "global",
            "arn": acc["AcceleratorArn"],
            "params": {"AcceleratorArn": acc["AcceleratorArn"]},
            "vars": [acc.get("Name")],
        }

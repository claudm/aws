"""Checks de AWS Lambda. Escopo regional.

FSBP Lambda.2 — Funções Lambda devem usar runtimes suportados.
"""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("lambda", "function")
def iter_functions(ctx: ScanContext):
    for fn in ctx.cached("lambda:functions", lambda: ctx.paginate("lambda", "list_functions", "Functions")):
        name = fn["FunctionName"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": fn.get("FunctionArn", ""),
            "params": {"FunctionName": name},
            "vars": [name],
        }

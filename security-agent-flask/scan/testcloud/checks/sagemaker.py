"""Checks de Amazon SageMaker. Escopo regional."""

from __future__ import annotations

from ..context import ScanContext
from ..registry import resource_provider

@resource_provider("sagemaker", "notebook")
def iter_notebooks(ctx: ScanContext):
    for nb in ctx.paginate("sagemaker", "list_notebook_instances", "NotebookInstances"):
        name = nb["NotebookInstanceName"]
        yield {
            "resource_id": name,
            "region": ctx.region,
            "arn": nb["NotebookInstanceArn"],
            "params": {"NotebookInstanceName": name},
            "vars": [name],
        }

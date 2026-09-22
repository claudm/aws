"""Importar este pacote popula o registry de checks.

Para adicionar um check novo: crie a função em um dos módulos (ou em um módulo
novo importado aqui) e decore com @check(...). Nada mais precisa ser alterado.
"""

from . import (  # noqa: F401
    cloudfront,
    compute,
    cost,
    databases,
    detective,
    ec2,
    iam,
    s3,
    sns,
    sqs,
)

__all__ = [
    "cloudfront",
    "compute",
    "cost",
    "databases",
    "detective",
    "ec2",
    "iam",
    "s3",
    "sns",
    "sqs",
]

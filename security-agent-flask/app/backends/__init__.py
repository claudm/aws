"""Backends de dados: `real` (AWS de verdade) e `memory` (MockState).

Os dois módulos expõem **exatamente as mesmas funções, com as mesmas
assinaturas**. Nenhuma delas tem os dois caminhos dentro: em dev chama-se a
mesma função, só que a do mock.

Este pacote é o único ponto do app que decide qual dos dois usar. Quem consome
é `providers.py`, que só repassa a chamada.
"""
from __future__ import annotations

from types import ModuleType

from ..config import get_settings


def get_backend() -> ModuleType:
    """Módulo do backend ativo, escolhido por SA_BACKEND.

    Import tardio de propósito: em modo memory nem `real` nem `securityagent`
    chegam a ser carregados. (O boto3 ainda entra, por `aws.py`, que o
    `memory` usa só para o validador de ARN — nenhuma chamada AWS acontece.)
    """
    if get_settings().sa_backend == "memory":
        from . import memory
        return memory
    from . import real
    return real

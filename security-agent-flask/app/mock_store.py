"""Mock de Spaces e Pentests: dados em JSON, sem DynamoDB.

Implementa a mesma interface de `store.Store`, mas os registros vêm de
`mock_data.json` e vivem só na memória do processo. Escritas (criar Space,
criar/atualizar Pentest, verificar endpoint) ficam valendo enquanto o processo
estiver de pé e somem no restart — nada é gravado em tabela nenhuma.
"""
from __future__ import annotations

from .mock_data import load_mock_data
from .schemas import Pentest, Space
from .store import Store


class MockStore(Store):
    """Dados fake de domínio, carregados do JSON e servidos em memória."""

    def __init__(self) -> None:
        data = load_mock_data()
        self._spaces: dict[str, Space] = {
            s["space_id"]: Space(**s) for s in data.get("spaces", [])
        }
        self._pentests: dict[str, Pentest] = {
            p["id"]: Pentest(**p) for p in data.get("pentests", [])
        }

    # ---- Spaces ----
    def upsert_space(self, space: Space) -> Space:
        self._spaces[space.space_id] = space
        return space

    def get_space(self, space_id: str) -> Space | None:
        return self._spaces.get(space_id)

    def list_spaces(self, account_id: str, region: str) -> list[Space]:
        return [
            s for s in self._spaces.values()
            if s.account_id == account_id and s.region == region
        ]

    # ---- Pentests ----
    def put_pentest(self, pentest: Pentest) -> Pentest:
        self._pentests[pentest.id] = pentest
        return pentest

    def get_pentest(self, pentest_id: str) -> Pentest | None:
        return self._pentests.get(pentest_id)

    def list_pentests(self, space_id: str) -> list[Pentest]:
        items = [p for p in self._pentests.values() if p.space_id == space_id]
        return sorted(items, key=lambda p: p.created_at, reverse=True)

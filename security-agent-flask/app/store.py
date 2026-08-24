"""Persistência de Spaces e Pentests (memory | dynamodb).

`memory` usa mock_store.MockStore: dados de `mock_data.json` servidos em
memória, sem tocar em DynamoDB. `dynamodb` é o único caminho que fala com a
AWS — boto3 só é importado quando esse backend é escolhido.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod

from .config import get_settings
from .errors import ApiError
from .schemas import Pentest, Space


class Store(ABC):
    @abstractmethod
    def upsert_space(self, space: Space) -> Space: ...
    @abstractmethod
    def get_space(self, space_id: str) -> Space | None: ...
    @abstractmethod
    def list_spaces(self, account_id: str, region: str) -> list[Space]: ...
    @abstractmethod
    def put_pentest(self, pentest: Pentest) -> Pentest: ...
    @abstractmethod
    def get_pentest(self, pentest_id: str) -> Pentest | None: ...
    @abstractmethod
    def list_pentests(self, space_id: str) -> list[Pentest]: ...


class DynamoStore(Store):
    def __init__(self) -> None:
        import boto3

        settings = get_settings()
        ddb = boto3.resource("dynamodb", region_name=settings.aws_region)
        self._spaces_tbl = ddb.Table(settings.ddb_spaces_table)
        self._pentests_tbl = ddb.Table(settings.ddb_pentests_table)

    def upsert_space(self, space: Space) -> Space:
        self._spaces_tbl.put_item(Item={"space_id": space.space_id, "data": space.model_dump_json()})
        return space

    def get_space(self, space_id: str) -> Space | None:
        item = self._spaces_tbl.get_item(Key={"space_id": space_id}).get("Item")
        return Space(**json.loads(item["data"])) if item else None

    def list_spaces(self, account_id: str, region: str) -> list[Space]:
        items = self._spaces_tbl.scan().get("Items", [])
        spaces = [Space(**json.loads(i["data"])) for i in items]
        return [s for s in spaces if s.account_id == account_id and s.region == region]

    def put_pentest(self, pentest: Pentest) -> Pentest:
        self._pentests_tbl.put_item(
            Item={"id": pentest.id, "space_id": pentest.space_id, "data": pentest.model_dump_json()}
        )
        return pentest

    def get_pentest(self, pentest_id: str) -> Pentest | None:
        item = self._pentests_tbl.get_item(Key={"id": pentest_id}).get("Item")
        return Pentest(**json.loads(item["data"])) if item else None

    def list_pentests(self, space_id: str) -> list[Pentest]:
        items = self._pentests_tbl.scan().get("Items", [])
        pentests = [Pentest(**json.loads(i["data"])) for i in items]
        pentests = [p for p in pentests if p.space_id == space_id]
        return sorted(pentests, key=lambda p: p.created_at, reverse=True)


_store: Store | None = None


def get_store() -> Store:
    global _store
    if _store is None:
        if get_settings().store_backend == "dynamodb":
            _store = DynamoStore()
        else:
            from .mock_store import MockStore

            _store = MockStore()
    return _store


def require_space(space_id: str) -> Space:
    space = get_store().get_space(space_id)
    if not space:
        raise ApiError(404, f"Space '{space_id}' não encontrado")
    return space


def require_pentest(pentest_id: str) -> Pentest:
    pentest = get_store().get_pentest(pentest_id)
    if not pentest:
        raise ApiError(404, f"Pentest '{pentest_id}' não encontrado")
    return pentest

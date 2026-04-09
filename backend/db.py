from __future__ import annotations

from typing import Any
from uuid import uuid4

from motor.motor_asyncio import AsyncIOMotorClient

from core.config import settings


class MemoryCollection:
    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}

    async def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
        for item in self._items.values():
            if all(item.get(key) == value for key, value in query.items()):
                return item
        return None

    async def insert_one(self, document: dict[str, Any]) -> Any:
        identifier = document.get("_id", str(uuid4()))
        document["_id"] = identifier
        self._items[identifier] = document

        class Result:
            inserted_id = identifier

        return Result()

    async def update_one(self, query: dict[str, Any], update: dict[str, Any], upsert: bool = False) -> Any:
        item = await self.find_one(query)
        if item is None and upsert:
            item = {**query}
            await self.insert_one(item)
        if item is not None and "$set" in update:
            item.update(update["$set"])
        return type("UpdateResult", (), {"matched_count": 1 if item else 0})()

    def find(self, query: dict[str, Any]) -> "MemoryCursor":
        items = [item for item in self._items.values() if all(item.get(key) == value for key, value in query.items())]
        return MemoryCursor(items)


class MemoryCursor:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self._items = items

    def sort(self, key: str, direction: int) -> "MemoryCursor":
        reverse = direction == -1
        self._items = sorted(self._items, key=lambda item: item.get(key), reverse=reverse)
        return self

    def limit(self, count: int) -> "MemoryCursor":
        self._items = self._items[:count]
        return self

    async def to_list(self, length: int | None = None) -> list[dict[str, Any]]:
        return self._items if length is None else self._items[:length]


class Database:
    def __init__(self) -> None:
        self.client: AsyncIOMotorClient | None = None
        self.db = None
        self.memory = {
            "users": MemoryCollection(),
            "scans": MemoryCollection(),
            "auth_profiles": MemoryCollection(),
        }

    async def connect(self) -> None:
        try:
            self.client = AsyncIOMotorClient(settings.mongo_uri, serverSelectionTimeoutMS=1500)
            await self.client.admin.command("ping")
            self.db = self.client[settings.mongo_db]
        except Exception:
            self.client = None
            self.db = None

    async def close(self) -> None:
        if self.client is not None:
            self.client.close()

    @property
    def users(self):  # noqa: ANN201
        return self.db["users"] if self.db is not None else self.memory["users"]

    @property
    def scans(self):  # noqa: ANN201
        return self.db["scans"] if self.db is not None else self.memory["scans"]

    @property
    def auth_profiles(self):  # noqa: ANN201
        return self.db["auth_profiles"] if self.db is not None else self.memory["auth_profiles"]


database = Database()

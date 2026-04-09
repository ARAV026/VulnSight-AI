from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from db import database


class UserRepository:
    async def create(self, name: str, email: str, password_hash: str) -> dict[str, Any]:
        record = {
            "_id": str(uuid4()),
            "name": name,
            "email": email.lower(),
            "password_hash": password_hash,
            "created_at": datetime.now(UTC),
        }
        await database.users.insert_one(record)
        return record

    async def get_by_email(self, email: str) -> dict[str, Any] | None:
        return await database.users.find_one({"email": email.lower()})

    async def get_by_id(self, user_id: str) -> dict[str, Any] | None:
        return await database.users.find_one({"_id": user_id})


class ScanRepository:
    async def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        document = {"_id": payload["scan_id"], **payload}
        await database.scans.insert_one(document)
        return document

    async def update(self, scan_id: str, payload: dict[str, Any]) -> None:
        await database.scans.update_one({"_id": scan_id}, {"$set": payload}, upsert=False)

    async def get(self, scan_id: str, user_id: str) -> dict[str, Any] | None:
        return await database.scans.find_one({"_id": scan_id, "user_id": user_id})

    async def list_for_user(self, user_id: str, limit: int = 20) -> list[dict[str, Any]]:
        return await database.scans.find({"user_id": user_id}).sort("created_at", -1).limit(limit).to_list(length=limit)


class AuthProfileRepository:
    async def create(self, payload: dict[str, Any]) -> dict[str, Any]:
        document = {"_id": payload["id"], **payload}
        await database.auth_profiles.insert_one(document)
        return document

    async def list_for_user(self, user_id: str, target_host: str | None = None) -> list[dict[str, Any]]:
        query: dict[str, Any] = {"user_id": user_id}
        if target_host:
            query["target_host"] = target_host
        return await database.auth_profiles.find(query).sort("created_at", -1).limit(50).to_list(length=50)

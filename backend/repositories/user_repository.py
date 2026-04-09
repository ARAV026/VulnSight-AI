from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from motor.motor_asyncio import AsyncIOMotorDatabase

from auth import hash_password
from models import UserPublic, UserRegisterRequest


def _serialize_user(document: dict[str, Any]) -> UserPublic:
    return UserPublic(
        id=str(document["_id"]),
        email=document["email"],
        full_name=document["full_name"],
        created_at=document["created_at"],
    )


async def create_user(database: AsyncIOMotorDatabase, payload: UserRegisterRequest) -> UserPublic:
    document = {
        "email": payload.email.lower(),
        "full_name": payload.full_name,
        "password_hash": hash_password(payload.password),
        "created_at": datetime.now(UTC),
    }
    result = await database.users.insert_one(document)
    document["_id"] = result.inserted_id
    return _serialize_user(document)


async def find_user_by_email(database: AsyncIOMotorDatabase, email: str) -> dict[str, Any] | None:
    return await database.users.find_one({"email": email.lower()})


async def get_user_by_id(database: AsyncIOMotorDatabase, user_id: str) -> UserPublic | None:
    try:
        object_id = ObjectId(user_id)
    except InvalidId:
        return None
    document = await database.users.find_one({"_id": object_id})
    return _serialize_user(document) if document else None

from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from config import settings

client = AsyncIOMotorClient(settings.mongo_uri)
database: AsyncIOMotorDatabase = client[settings.mongo_db_name]


def get_database() -> AsyncIOMotorDatabase:
    return database

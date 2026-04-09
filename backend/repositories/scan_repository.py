from __future__ import annotations

from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from models import ScanHistoryResponse, ScanListItem, ScanResult


async def save_scan(database: AsyncIOMotorDatabase, result: ScanResult) -> None:
    document = result.model_dump(mode="json")
    await database.scans.update_one({"scan_id": result.scan_id}, {"$set": document}, upsert=True)


async def get_scan(database: AsyncIOMotorDatabase, scan_id: str, user_id: str) -> ScanResult | None:
    document = await database.scans.find_one({"scan_id": scan_id, "user_id": user_id})
    return ScanResult(**document) if document else None


async def list_scans(database: AsyncIOMotorDatabase, user_id: str, limit: int = 25) -> ScanHistoryResponse:
    cursor = database.scans.find({"user_id": user_id}).sort("created_at", -1).limit(limit)
    items: list[ScanListItem] = []
    async for document in cursor:
        items.append(
            ScanListItem(
                scan_id=document["scan_id"],
                target_url=document["target_url"],
                profile=document["profile"],
                status=document["status"],
                created_at=document["created_at"],
                completed_at=document.get("completed_at"),
                score=document["analysis"]["summary"]["score"],
                total_findings=document["analysis"]["summary"]["total_findings"],
                scan_mode=document.get("scan_mode", "heuristic"),
            )
        )
    return ScanHistoryResponse(items=items)

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from io import BytesIO
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from core.config import settings
from data_access import AuthProfileRepository, ScanRepository
from db import database
from models import (
    AnalysisRequest,
    AnalysisResponse,
    AuthDiscoveryRequest,
    AuthDiscoveryResponse,
    AuthProfileCreate,
    HealthResponse,
    SavedAuthProfile,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    ScanResult,
)
from services.analysis_engine import analyze_findings, build_diff
from services.auth_discovery import discover_auth
from services.reporting import build_pdf_report
from services.scanner_engine import execute_scan


@asynccontextmanager
async def lifespan(_: FastAPI):
    await database.connect()
    yield
    await database.close()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scans = ScanRepository()
auth_profiles = AuthProfileRepository()
SCAN_TASKS: dict[str, asyncio.Task[Any]] = {}

GUEST_USER = "guest-user"


# ---------------- HEALTH ROUTES ---------------- #

@app.get("/", response_model=HealthResponse)
async def home() -> HealthResponse:
    return HealthResponse(
        message="VulnSight AI Backend Running",
        status="ok"
    )


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        message="healthy",
        status="ok"
    )


# ---------------- AUTH DISCOVERY ---------------- #

@app.post("/auth/discover", response_model=AuthDiscoveryResponse)
async def auth_discover(payload: AuthDiscoveryRequest) -> AuthDiscoveryResponse:
    return await asyncio.to_thread(
        discover_auth,
        str(payload.target_url),
        payload.headers,
        payload.cookies
    )


@app.post(
    "/auth/profiles",
    response_model=SavedAuthProfile,
    status_code=status.HTTP_201_CREATED
)
async def create_auth_profile(payload: AuthProfileCreate) -> SavedAuthProfile:
    from urllib.parse import urlparse

    profile_id = str(uuid4())

    document = await auth_profiles.create(
        {
            "id": profile_id,
            "user_id": GUEST_USER,
            "target_host": urlparse(str(payload.target_url)).netloc,
            "profile_name": payload.profile_name,
            "context": payload.context.model_dump(),
            "created_at": datetime.now(UTC),
        }
    )

    return SavedAuthProfile(
        **{k: v for k, v in document.items() if k != "_id"}
    )


@app.get("/auth/profiles", response_model=list[SavedAuthProfile])
async def list_auth_profiles(
    target_url: str | None = None
) -> list[SavedAuthProfile]:
    from urllib.parse import urlparse

    host = urlparse(target_url).netloc if target_url else None
    items = await auth_profiles.list_for_user(GUEST_USER, host)

    return [
        SavedAuthProfile(
            **{k: v for k, v in item.items() if k != "_id"}
        )
        for item in items
    ]


# ---------------- SCAN ROUTES ---------------- #

@app.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED
)
async def scan_target(payload: ScanRequest) -> ScanResponse:
    scan_id = str(uuid4())
    now = datetime.now(UTC)

    await scans.create(
        {
            "scan_id": scan_id,
            "user_id": GUEST_USER,
            "target_url": str(payload.target_url),
            "profile": payload.profile,
            "status": "queued",
            "findings": [],
            "analysis": None,
            "engine": "queued",
            "progress": 0,
            "message": "Scan queued",
            "zap_session": None,
            "context": payload.context.model_dump(),
            "compare_with_scan_id": payload.compare_with_scan_id,
            "created_at": now,
            "updated_at": now,
        }
    )

    SCAN_TASKS[scan_id] = asyncio.create_task(
        _run_scan_job(scan_id, payload)
    )

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        progress=0,
        message="Scan queued"
    )


@app.get("/results/{scan_id}", response_model=ScanResult)
async def get_results(scan_id: str) -> ScanResult:
    result = await scans.get(scan_id, GUEST_USER)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return ScanResult(**_normalize_scan_document(result))


@app.get("/history", response_model=list[ScanHistoryItem])
async def history() -> list[ScanHistoryItem]:
    items = await scans.list_for_user(GUEST_USER)

    return [
        ScanHistoryItem(
            scan_id=item["scan_id"],
            target_url=item["target_url"],
            profile=item["profile"],
            status=item["status"],
            score=(item.get("analysis") or {}).get("summary", {}).get("score", 0),
            total_findings=len(item.get("findings") or []),
            engine=item.get("engine", "heuristic"),
            progress=item.get("progress", 0),
            created_at=item["created_at"],
        )
        for item in items
    ]


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(payload: AnalysisRequest) -> AnalysisResponse:
    return analyze_findings(
        payload.findings,
        str(payload.target_url)
    )


@app.get("/report/{scan_id}")
async def report(scan_id: str) -> StreamingResponse:
    result = await scans.get(scan_id, GUEST_USER)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    scan_result = ScanResult(**_normalize_scan_document(result))

    pdf_data = BytesIO()
    build_pdf_report(scan_result, pdf_data)
    pdf_data.seek(0)

    headers = {
        "Content-Disposition":
        f'attachment; filename="vulnsight-report-{scan_id}.pdf"'
    }

    return StreamingResponse(
        pdf_data,
        media_type="application/pdf",
        headers=headers
    )


# ---------------- BACKGROUND SCAN JOB ---------------- #

async def _run_scan_job(scan_id: str, payload: ScanRequest) -> None:
    try:
        await _update_scan(
            scan_id,
            {
                "status": "running",
                "progress": 15,
                "engine": "initializing",
                "message": "Preparing scan",
            },
        )

        execution = await asyncio.to_thread(
            execute_scan,
            str(payload.target_url),
            payload.profile,
            payload.context
        )

        await _update_scan(
            scan_id,
            {
                "progress": 75,
                "engine": execution.engine,
                "message": "Analyzing findings",
            },
        )

        analysis = analyze_findings(
            execution.findings,
            str(payload.target_url),
            technologies=execution.technologies,
            risky_parameters=execution.risky_parameters,
            forms_discovered=execution.forms_discovered,
            get_forms=execution.get_forms,
            anomaly_observations=execution.anomaly_observations,
            page_risk_map=execution.page_risk_map,
            assets=execution.assets,
            ports=execution.ports,
        )

        diff = None

        if payload.compare_with_scan_id:
            baseline = await scans.get(
                payload.compare_with_scan_id,
                GUEST_USER
            )

            if baseline and baseline.get("analysis"):
                from models import Finding

                baseline_items = [
                    Finding(**item)
                    for item in baseline.get("findings", [])
                ]

                diff = build_diff(
                    scan_id,
                    payload.compare_with_scan_id,
                    execution.findings,
                    analysis.summary.score,
                    baseline_items,
                    (baseline.get("analysis") or {})
                    .get("summary", {})
                    .get("score", 0),
                )

                analysis.diff = diff

        await _update_scan(
            scan_id,
            {
                "status": "completed",
                "findings": [
                    item.model_dump()
                    for item in execution.findings
                ],
                "analysis": analysis.model_dump(),
                "engine": execution.engine,
                "progress": 100,
                "message": "Scan completed",
                "zap_session": execution.zap_session,
                "updated_at": datetime.now(UTC),
            },
        )

    except Exception as exc:
        await _update_scan(
            scan_id,
            {
                "status": "failed",
                "progress": 100,
                "message": f"Scan failed: {exc}",
                "engine": "failed",
                "updated_at": datetime.now(UTC),
            },
        )

    finally:
        SCAN_TASKS.pop(scan_id, None)


# ---------------- HELPERS ---------------- #

async def _update_scan(scan_id: str, payload: dict[str, Any]) -> None:
    payload["updated_at"] = datetime.now(UTC)
    await scans.update(scan_id, payload)


def _normalize_scan_document(document: dict[str, Any]) -> dict[str, Any]:
    normalized = document.copy()
    normalized.pop("_id", None)
    return normalized
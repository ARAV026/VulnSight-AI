from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from io import BytesIO
from typing import Any
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from core.config import settings
from core.security import create_access_token, hash_password, verify_password
from data_access import AuthProfileRepository, ScanRepository, UserRepository
from db import database
from dependencies import get_current_user
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
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)
from services.analysis_engine import analyze_findings, build_diff
from services.auth_discovery import discover_auth
from services.reporting import build_pdf_report
from services.scanner_engine import ScanExecutionResult, execute_scan


@asynccontextmanager
async def lifespan(_: FastAPI):
    await database.connect()
    yield
    await database.close()


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users = UserRepository()
scans = ScanRepository()
auth_profiles = AuthProfileRepository()
SCAN_TASKS: dict[str, asyncio.Task[Any]] = {}


@app.get("/", response_model=HealthResponse)
async def home() -> HealthResponse:
    return HealthResponse(message="VulnSight AI Backend Running", status="ok")


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(message="healthy", status="ok")


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate) -> TokenResponse:
    existing = await users.get_by_email(payload.email)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Email already registered")
    record = await users.create(payload.name, payload.email, hash_password(payload.password))
    return _token_response(record)


@app.post("/auth/login", response_model=TokenResponse)
async def login(payload: UserLogin) -> TokenResponse:
    record = await users.get_by_email(payload.email)
    if record is None or not verify_password(payload.password, record["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return _token_response(record)


@app.get("/auth/me", response_model=UserResponse)
async def me(current_user: dict[str, Any] = Depends(get_current_user)) -> UserResponse:
    return _user_response(current_user)


@app.post("/auth/discover", response_model=AuthDiscoveryResponse)
async def auth_discover(payload: AuthDiscoveryRequest, _: dict[str, Any] = Depends(get_current_user)) -> AuthDiscoveryResponse:
    return await asyncio.to_thread(discover_auth, str(payload.target_url), payload.headers, payload.cookies)


@app.post("/auth/profiles", response_model=SavedAuthProfile, status_code=status.HTTP_201_CREATED)
async def create_auth_profile(payload: AuthProfileCreate, current_user: dict[str, Any] = Depends(get_current_user)) -> SavedAuthProfile:
    from urllib.parse import urlparse
    profile_id = str(uuid4())
    document = await auth_profiles.create(
        {
            "id": profile_id,
            "user_id": current_user["_id"],
            "target_host": urlparse(str(payload.target_url)).netloc,
            "profile_name": payload.profile_name,
            "context": payload.context.model_dump(),
            "created_at": datetime.now(UTC),
        }
    )
    return SavedAuthProfile(**{k: v for k, v in document.items() if k != "_id"})


@app.get("/auth/profiles", response_model=list[SavedAuthProfile])
async def list_auth_profiles(target_url: str | None = None, current_user: dict[str, Any] = Depends(get_current_user)) -> list[SavedAuthProfile]:
    from urllib.parse import urlparse
    host = urlparse(target_url).netloc if target_url else None
    items = await auth_profiles.list_for_user(current_user["_id"], host)
    return [SavedAuthProfile(**{k: v for k, v in item.items() if k != "_id"}) for item in items]


@app.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def scan_target(payload: ScanRequest, current_user: dict[str, Any] = Depends(get_current_user)) -> ScanResponse:
    scan_id = str(uuid4())
    now = datetime.now(UTC)
    await scans.create(
        {
            "scan_id": scan_id,
            "user_id": current_user["_id"],
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
    SCAN_TASKS[scan_id] = asyncio.create_task(_run_scan_job(scan_id, current_user["_id"], payload))
    return ScanResponse(scan_id=scan_id, status="queued", progress=0, message="Scan queued")


@app.get("/results/{scan_id}", response_model=ScanResult)
async def get_results(scan_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> ScanResult:
    result = await scans.get(scan_id, current_user["_id"])
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResult(**_normalize_scan_document(result))


@app.get("/history", response_model=list[ScanHistoryItem])
async def history(current_user: dict[str, Any] = Depends(get_current_user)) -> list[ScanHistoryItem]:
    items = await scans.list_for_user(current_user["_id"])
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
async def analyze(payload: AnalysisRequest, _: dict[str, Any] = Depends(get_current_user)) -> AnalysisResponse:
    return analyze_findings(payload.findings, str(payload.target_url))


@app.get("/report/{scan_id}")
async def report(scan_id: str, current_user: dict[str, Any] = Depends(get_current_user)) -> StreamingResponse:
    result = await scans.get(scan_id, current_user["_id"])
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan_result = ScanResult(**_normalize_scan_document(result))
    pdf_data = BytesIO()
    build_pdf_report(scan_result, pdf_data)
    pdf_data.seek(0)
    headers = {"Content-Disposition": f'attachment; filename="vulnsight-report-{scan_id}.pdf"'}
    return StreamingResponse(pdf_data, media_type="application/pdf", headers=headers)


async def _run_scan_job(scan_id: str, user_id: str, payload: ScanRequest) -> None:
    try:
        await _update_scan(scan_id, {"status": "running", "progress": 15, "engine": "initializing", "message": "Preparing session-aware scan"})
        execution = await asyncio.to_thread(execute_scan, str(payload.target_url), payload.profile, payload.context)
        await _update_scan(scan_id, {"progress": 75, "engine": execution.engine, "message": "Analyzing findings and attack surface"})
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
            baseline = await scans.get(payload.compare_with_scan_id, user_id)
            if baseline and baseline.get("analysis"):
                from models import Finding
                baseline_items = [Finding(**item) for item in baseline.get("findings", [])]
                diff = build_diff(
                    scan_id,
                    payload.compare_with_scan_id,
                    execution.findings,
                    analysis.summary.score,
                    baseline_items,
                    (baseline.get("analysis") or {}).get("summary", {}).get("score", 0),
                )
                analysis.diff = diff
        await _update_scan(
            scan_id,
            {
                "status": "completed",
                "findings": [item.model_dump() for item in execution.findings],
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


async def _update_scan(scan_id: str, payload: dict[str, Any]) -> None:
    payload["updated_at"] = datetime.now(UTC)
    await scans.update(scan_id, payload)


def _token_response(record: dict[str, Any]) -> TokenResponse:
    return TokenResponse(access_token=create_access_token(record["_id"]), user=_user_response(record))


def _user_response(record: dict[str, Any]) -> UserResponse:
    return UserResponse(id=record["_id"], name=record["name"], email=record["email"], created_at=record["created_at"])


def _normalize_scan_document(document: dict[str, Any]) -> dict[str, Any]:
    normalized = document.copy()
    normalized.pop("_id", None)
    return normalized

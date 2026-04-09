from __future__ import annotations

from datetime import UTC, datetime
from typing import Dict, List, Literal

from pydantic import BaseModel, EmailStr, Field, HttpUrl

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]
ScanProfile = Literal["quick", "balanced", "deep"]
ScanStatus = Literal["queued", "running", "completed", "failed"]
AuthMode = Literal["none", "basic", "bearer", "form"]
AssetType = Literal["script", "stylesheet", "image", "font", "document", "other"]


class LoginStep(BaseModel):
    method: Literal["GET", "POST"] = "POST"
    url: HttpUrl
    username_field: str | None = "username"
    password_field: str | None = "password"
    username_value: str | None = None
    password_value: str | None = None
    static_fields: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)


class RequestContext(BaseModel):
    auth_mode: AuthMode = "none"
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    bearer_token: str | None = None
    username: str | None = None
    password: str | None = None
    login_url: HttpUrl | None = None
    username_field: str = "username"
    password_field: str = "password"
    extra_login_fields: Dict[str, str] = Field(default_factory=dict)
    login_steps: List[LoginStep] = Field(default_factory=list)


class AuthDiscoveryCandidate(BaseModel):
    login_url: str
    method: Literal["get", "post"]
    username_field: str | None = None
    password_field: str | None = None
    csrf_fields: List[str] = Field(default_factory=list)
    hidden_fields: Dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)


class AuthDiscoveryRequest(BaseModel):
    target_url: HttpUrl
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)


class AuthDiscoveryResponse(BaseModel):
    suggested_auth_type: Literal["none", "form", "basic", "bearer"]
    candidates: List[AuthDiscoveryCandidate] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SavedAuthProfile(BaseModel):
    id: str
    target_host: str
    profile_name: str
    context: RequestContext
    created_at: datetime


class AuthProfileCreate(BaseModel):
    target_url: HttpUrl
    profile_name: str = Field(min_length=2, max_length=100)
    context: RequestContext


class Finding(BaseModel):
    title: str
    category: str
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    endpoint: str
    description: str
    impact: str
    evidence: str
    remediation: str
    cwe: str
    tags: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


class AssetRecord(BaseModel):
    url: str
    asset_type: AssetType
    source_page: str
    external: bool


class PortObservation(BaseModel):
    port: int
    protocol: Literal["tcp"] = "tcp"
    state: Literal["open", "closed", "filtered"]
    service_hint: str | None = None
    note: str = ""


class PageRisk(BaseModel):
    url: str
    status_code: int
    forms: int
    risky_parameters: List[str] = Field(default_factory=list)
    findings: int = 0
    risk_score: int = 0
    technologies: List[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    target_url: HttpUrl
    profile: ScanProfile = "balanced"
    context: RequestContext = Field(default_factory=RequestContext)
    compare_with_scan_id: str | None = None


class AnalysisRequest(BaseModel):
    target_url: HttpUrl
    findings: List[Finding]


class RiskDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class Summary(BaseModel):
    score: int
    total_findings: int
    exploitability: int
    false_positive_risk: int
    attack_surface: int


class Recommendation(BaseModel):
    priority: Literal["immediate", "high", "medium", "backlog"]
    title: str
    action: str


class TechnologyFingerprint(BaseModel):
    name: str
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    hardening_advice: str


class ParameterObservation(BaseModel):
    parameter: str
    location: Literal["query", "form", "header"]
    baseline_status: int | None = None
    comparison_status: int | None = None
    baseline_length: int | None = None
    comparison_length: int | None = None
    anomaly_score: int = 0
    note: str


class RemediationStatus(BaseModel):
    area: str
    status: Literal["open", "monitor", "partially_mitigated"]
    note: str


class AIDetectionSummary(BaseModel):
    model_version: str = "hybrid-v1"
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    threshold: float = 0.85
    high_confidence_findings: int = 0
    feedback_samples: int = 0
    notes: List[str] = Field(default_factory=list)


class AttackSurfaceSummary(BaseModel):
    risky_parameters: List[str] = Field(default_factory=list)
    forms_discovered: int = 0
    get_forms: int = 0
    anomaly_observations: List[ParameterObservation] = Field(default_factory=list)


class ScanDiff(BaseModel):
    baseline_scan_id: str
    current_scan_id: str
    new_findings: List[str] = Field(default_factory=list)
    resolved_findings: List[str] = Field(default_factory=list)
    score_delta: int = 0
    total_findings_delta: int = 0


class AnalysisResponse(BaseModel):
    summary: Summary
    risk_distribution: RiskDistribution
    attack_patterns: List[str]
    recommendations: List[Recommendation]
    technologies: List[TechnologyFingerprint] = Field(default_factory=list)
    attack_surface_summary: AttackSurfaceSummary = Field(default_factory=AttackSurfaceSummary)
    remediation_status: List[RemediationStatus] = Field(default_factory=list)
    ai_summary: AIDetectionSummary = Field(default_factory=AIDetectionSummary)
    page_risk_map: List[PageRisk] = Field(default_factory=list)
    assets: List[AssetRecord] = Field(default_factory=list)
    ports: List[PortObservation] = Field(default_factory=list)
    diff: ScanDiff | None = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    summary: Summary | None = None
    progress: int = 0
    message: str | None = None


class ScanResult(BaseModel):
    scan_id: str
    user_id: str | None = None
    target_url: HttpUrl
    profile: ScanProfile
    status: ScanStatus
    findings: List[Finding]
    analysis: AnalysisResponse | None = None
    engine: str = "heuristic"
    progress: int = 0
    message: str | None = None
    zap_session: str | None = None
    context: RequestContext = Field(default_factory=RequestContext)
    compare_with_scan_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanHistoryItem(BaseModel):
    scan_id: str
    target_url: str
    profile: ScanProfile
    status: ScanStatus
    score: int
    total_findings: int
    engine: str
    progress: int
    created_at: datetime


class HealthResponse(BaseModel):
    message: str
    status: Literal["ok"]


class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: str
    name: str
    email: EmailStr
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user: UserResponse

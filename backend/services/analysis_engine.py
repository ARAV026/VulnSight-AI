from __future__ import annotations

from typing import List

from models import AnalysisResponse, AssetRecord, AttackSurfaceSummary, Finding, PageRisk, ParameterObservation, PortObservation, Recommendation, RemediationStatus, RiskDistribution, ScanDiff, Summary, TechnologyFingerprint
from services.hybrid_ai import build_ai_summary

SEVERITY_WEIGHT = {"critical": 100, "high": 80, "medium": 55, "low": 25, "info": 5}


def analyze_findings(findings: List[Finding], target_url: str, technologies: list[TechnologyFingerprint] | None = None, risky_parameters: list[str] | None = None, forms_discovered: int = 0, get_forms: int = 0, anomaly_observations: list[ParameterObservation] | None = None, page_risk_map: list[PageRisk] | None = None, assets: list[AssetRecord] | None = None, ports: list[PortObservation] | None = None, diff: ScanDiff | None = None) -> AnalysisResponse:
    technologies = technologies or []
    risky_parameters = risky_parameters or []
    anomaly_observations = anomaly_observations or []
    page_risk_map = page_risk_map or []
    assets = assets or []
    ports = ports or []
    dist = RiskDistribution()
    patterns: list[str] = []
    recs: list[Recommendation] = []
    for f in findings:
        setattr(dist, f.severity, getattr(dist, f.severity) + 1)
        if f.category not in patterns:
            patterns.append(f.category)
        recs.append(_rec_for_finding(f))
    recs.extend([Recommendation(priority="medium", title=f"Framework Hardening: {t.name}", action=t.hardening_advice) for t in technologies])
    total = len(findings)
    weight = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    anomaly = max((x.anomaly_score for x in anomaly_observations), default=0)
    score = max(5, min(95, 100 - int((weight / max(total, 1)) + (anomaly / 10)))) if findings else 96
    return AnalysisResponse(
        summary=Summary(score=score, total_findings=total, exploitability=max(0, min(100, int((dist.critical * 25) + (dist.high * 15) + (dist.medium * 8) + (anomaly / 2)))), false_positive_risk=8 if anomaly > 20 else 12 if findings else 4, attack_surface=max(0, min(100, 15 + total * 9 + len(risky_parameters) * 3 + forms_discovered * 2))),
        risk_distribution=dist,
        attack_patterns=patterns or ["No attack patterns detected"],
        recommendations=_dedupe(recs)[:8] or [Recommendation(priority="backlog", title="Maintain baseline monitoring", action=f"Continue periodic validation of {target_url}.")],
        technologies=technologies,
        attack_surface_summary=AttackSurfaceSummary(risky_parameters=risky_parameters, forms_discovered=forms_discovered, get_forms=get_forms, anomaly_observations=anomaly_observations),
        remediation_status=_status(findings, technologies, risky_parameters, anomaly_observations),
        ai_summary=build_ai_summary(findings, forms_discovered),
        page_risk_map=page_risk_map,
        assets=assets,
        ports=ports,
        diff=diff,
    )


def build_diff(current_scan_id: str, baseline_scan_id: str, current_findings: list[Finding], current_score: int, baseline_findings: list[Finding], baseline_score: int) -> ScanDiff:
    current_keys = {f"{f.title}|{f.endpoint}|{f.cwe}" for f in current_findings}
    baseline_keys = {f"{f.title}|{f.endpoint}|{f.cwe}" for f in baseline_findings}
    return ScanDiff(
        baseline_scan_id=baseline_scan_id,
        current_scan_id=current_scan_id,
        new_findings=sorted(current_keys - baseline_keys),
        resolved_findings=sorted(baseline_keys - current_keys),
        score_delta=current_score - baseline_score,
        total_findings_delta=len(current_findings) - len(baseline_findings),
    )


def _rec_for_finding(finding: Finding) -> Recommendation:
    if finding.category == "SQL Injection":
        return Recommendation(priority="immediate" if finding.severity in {"critical", "high"} else "high", title="Harden Query Construction", action="Review data-access paths for parameterized statements, typed validation, safe ORM builders, and least-privilege roles.")
    priority = "immediate" if finding.severity == "critical" else "high" if finding.severity == "high" else "medium" if finding.severity == "medium" else "backlog"
    return Recommendation(priority=priority, title=f"Address {finding.category}", action=finding.remediation)


def _status(findings: list[Finding], technologies: list[TechnologyFingerprint], risky_parameters: list[str], anomalies: list[ParameterObservation]) -> list[RemediationStatus]:
    out: list[RemediationStatus] = []
    if risky_parameters:
        out.append(RemediationStatus(area="SQL Injection Surface", status="open" if max((a.anomaly_score for a in anomalies), default=0) >= 35 else "monitor", note=f"Review {len(risky_parameters)} risky parameter(s)."))
    if any(f.category == "Security Misconfiguration" for f in findings):
        out.append(RemediationStatus(area="Security Headers", status="open", note="One or more hardening controls are missing or weak."))
    if technologies:
        out.append(RemediationStatus(area="Technology Hardening", status="partially_mitigated", note=f"Detected {len(technologies)} stack marker(s); apply framework-specific hardening baselines."))
    return out or [RemediationStatus(area="Baseline", status="monitor", note="No priority remediation areas detected in this scan.")]


def _dedupe(items: list[Recommendation]) -> list[Recommendation]:
    seen: set[tuple[str, str]] = set()
    out: list[Recommendation] = []
    for item in items:
        key = (item.title, item.action)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return sorted(out, key=lambda item: {"immediate": 0, "high": 1, "medium": 2, "backlog": 3}[item.priority])

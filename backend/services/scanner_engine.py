from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from models import AssetRecord, Finding, LoginStep, PageRisk, ParameterObservation, PortObservation, RequestContext, ScanProfile, TechnologyFingerprint

SUSPICIOUS_NAMES = {"id", "user", "username", "email", "search", "query", "q", "filter", "sort", "category", "page", "item", "product"}
COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
}


@dataclass
class ScanExecutionResult:
    engine: str
    findings: list[Finding]
    zap_session: str | None
    technologies: list[TechnologyFingerprint]
    risky_parameters: list[str]
    forms_discovered: int
    get_forms: int
    anomaly_observations: list[ParameterObservation]
    page_risk_map: list[PageRisk]
    assets: list[AssetRecord]
    ports: list[PortObservation]


def execute_scan(target_url: str, profile: ScanProfile, context: RequestContext) -> ScanExecutionResult:
    session = _build_session(context)
    pages = _crawl(target_url, session, profile)
    tech = _fingerprint(" ".join(p["body"] for p in pages), _merge_headers(pages))
    forms = [f for p in pages for f in p["forms"]]
    risky = _discover_params(target_url, " ".join(p["body"] for p in pages), forms)
    anomalies = _compare(target_url, risky, session)
    assets = _assets_from_pages(pages, target_url)
    page_map = _page_map(pages)
    ports = _scan_ports(target_url, profile)
    findings = _findings(target_url, risky, forms, anomalies, tech, pages, ports)
    return ScanExecutionResult("heuristic", findings, None, tech, risky, len(forms), sum(1 for f in forms if f["method"] == "get"), anomalies, page_map, assets, ports)


def _build_session(context: RequestContext) -> requests.Session:
    s = requests.Session()
    s.headers.update(context.headers)
    s.cookies.update(context.cookies)
    if context.auth_mode == "bearer" and context.bearer_token:
        s.headers["Authorization"] = f"Bearer {context.bearer_token}"
    elif context.auth_mode == "basic" and context.username and context.password:
        s.auth = (context.username, context.password)
    if context.login_steps:
        for step in context.login_steps:
            _login_step(s, step, context)
    elif context.auth_mode == "form" and context.login_url and context.username and context.password:
        data = {context.username_field: context.username, context.password_field: context.password, **context.extra_login_fields}
        try:
            s.post(str(context.login_url), data=data, timeout=8, allow_redirects=True)
        except requests.RequestException:
            pass
    return s


def _login_step(session: requests.Session, step: LoginStep, context: RequestContext) -> None:
    data = dict(step.static_fields)
    if step.username_field and (step.username_value or context.username):
        data[step.username_field] = step.username_value or context.username or ""
    if step.password_field and (step.password_value or context.password):
        data[step.password_field] = step.password_value or context.password or ""
    try:
        if step.method == "GET":
            session.get(str(step.url), params=data, headers=step.headers, timeout=8, allow_redirects=True)
        else:
            session.post(str(step.url), data=data, headers=step.headers, timeout=8, allow_redirects=True)
    except requests.RequestException:
        pass


class _Parser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict[str, Any]] = []
        self.assets: list[dict[str, str]] = []
        self.links: list[str] = []
        self.active: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self.active = {"action": urljoin(self.base_url, a.get("action") or self.base_url), "method": (a.get("method") or "get").lower(), "inputs": []}
        elif tag in {"input", "textarea", "select"} and self.active is not None and a.get("name"):
            self.active["inputs"].append({"name": a["name"], "type": (a.get("type") or tag).lower()})
        elif tag == "script" and a.get("src"):
            self.assets.append({"url": urljoin(self.base_url, a["src"]), "type": "script"})
        elif tag == "link" and a.get("href"):
            rel = (a.get("rel") or "").lower()
            self.assets.append({"url": urljoin(self.base_url, a["href"]), "type": "stylesheet" if "stylesheet" in rel else "document"})
        elif tag == "img" and a.get("src"):
            self.assets.append({"url": urljoin(self.base_url, a["src"]), "type": "image"})
        elif tag == "a" and a.get("href"):
            href = a["href"]
            if not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(urljoin(self.base_url, href))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self.active is not None:
            self.forms.append(self.active)
            self.active = None


def _crawl(target_url: str, session: requests.Session, profile: ScanProfile) -> list[dict[str, Any]]:
    limit = 4 if profile == "quick" else 8 if profile == "balanced" else 12
    queue = [target_url, urljoin(target_url, "/robots.txt"), urljoin(target_url, "/sitemap.xml")]
    seen: set[str] = set()
    pages: list[dict[str, Any]] = []
    while queue and len(pages) < limit:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            r = session.get(url, timeout=6, allow_redirects=True)
            raw = r.text
            body = raw.lower()
            parser = _Parser(r.url)
            parser.feed(raw)
            pages.append({"url": r.url, "status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()}, "body": body, "forms": parser.forms, "assets": parser.assets})
            for link in parser.links[:20]:
                if urlparse(link).netloc == urlparse(target_url).netloc and link not in seen and link not in queue:
                    queue.append(link)
        except requests.RequestException:
            continue
    return pages


def _discover_params(target_url: str, body: str, forms: list[dict[str, Any]]) -> list[str]:
    out = set(parse_qs(urlparse(target_url).query).keys())
    for form in forms:
        for field in form["inputs"]:
            n = field["name"].lower()
            if n in SUSPICIOUS_NAMES or field["type"] in {"search", "text", "hidden", "number"}:
                out.add(field["name"])
    for token in SUSPICIOUS_NAMES:
        if f'name="{token}"' in body or f"name='{token}'" in body:
            out.add(token)
    return sorted(out)


def _compare(target_url: str, params: list[str], session: requests.Session) -> list[ParameterObservation]:
    obs: list[ParameterObservation] = []
    for p in params[:6]:
        try:
            a = session.get(_with_param(target_url, p, "1"), timeout=6)
            b = session.get(_with_param(target_url, p, "2"), timeout=6)
            score = min(100, abs(len(a.text) - len(b.text)) // 20)
            if a.status_code != b.status_code:
                score = max(score, 40)
            obs.append(ParameterObservation(parameter=p, location="query", baseline_status=a.status_code, comparison_status=b.status_code, baseline_length=len(a.text), comparison_length=len(b.text), anomaly_score=score, note="Benign response comparison completed."))
        except requests.RequestException:
            obs.append(ParameterObservation(parameter=p, location="query", anomaly_score=0, note="Comparison failed."))
    return obs


def _with_param(url: str, key: str, value: str) -> str:
    p = urlparse(url)
    q = parse_qs(p.query)
    q[key] = [value]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def _fingerprint(body: str, headers: dict[str, str]) -> list[TechnologyFingerprint]:
    items: list[TechnologyFingerprint] = []
    def add(n: str, c: str, conf: float, ev: str, adv: str) -> None:
        if not any(x.name == n for x in items):
            items.append(TechnologyFingerprint(name=n, category=c, confidence=conf, evidence=ev, hardening_advice=adv))
    powered = headers.get("x-powered-by", "")
    server = headers.get("server", "")
    if "php" in powered or "php" in body: add("PHP", "backend", 0.86, powered or "body marker", "Patch runtime and review raw SQL usage.")
    if "asp.net" in powered or "asp.net" in body: add("ASP.NET", "backend", 0.84, powered or "body marker", "Disable verbose headers and enforce anti-forgery.")
    if "wordpress" in body or "wp-content" in body: add("WordPress", "cms", 0.9, "wp-content marker", "Harden plugins/themes and protect admin paths.")
    if "react" in body or "data-reactroot" in body: add("React", "frontend", 0.68, "React marker", "Pair output encoding with CSP.")
    if "nginx" in server.lower(): add("Nginx", "server", 0.75, server, "Minimize banner exposure and review proxy hardening.")
    if re.search(r"laravel", body): add("Laravel", "backend", 0.7, "framework marker", "Review APP_DEBUG and query handling.")
    return items


def _page_map(pages: list[dict[str, Any]]) -> list[PageRisk]:
    out: list[PageRisk] = []
    for p in pages:
        risky = _discover_params(p["url"], p["body"], p["forms"])
        score = min(100, len(risky) * 10 + len(p["forms"]) * 8 + (15 if "/admin" in p["url"] or "/login" in p["url"] else 0))
        out.append(PageRisk(url=p["url"], status_code=p["status"], forms=len(p["forms"]), risky_parameters=risky, findings=0, risk_score=score, technologies=[]))
    return out


def _assets_from_pages(pages: list[dict[str, Any]], target_url: str) -> list[AssetRecord]:
    host = urlparse(target_url).netloc
    out: list[AssetRecord] = []
    seen: set[tuple[str, str]] = set()
    for p in pages:
        for a in p["assets"]:
            key = (a["url"], p["url"])
            if key in seen:
                continue
            seen.add(key)
            parsed = urlparse(a["url"])
            out.append(AssetRecord(url=a["url"], asset_type=a["type"], source_page=p["url"], external=bool(parsed.netloc and parsed.netloc != host)))
    return out[:80]


def _findings(target_url: str, risky: list[str], forms: list[dict[str, Any]], anomalies: list[ParameterObservation], tech: list[TechnologyFingerprint], pages: list[dict[str, Any]], ports: list[PortObservation]) -> list[Finding]:
    out: list[Finding] = []
    if risky:
        mx = max((o.anomaly_score for o in anomalies), default=0)
        out.append(Finding(title="Potential SQL Injection Surface", category="SQL Injection", severity="high" if mx >= 35 else "medium", confidence=0.84 if mx >= 35 else 0.78, endpoint=target_url, description="Parameters and workflows suggest query construction risk.", impact="Weak query handling can expose or alter data.", evidence=f"Parameters: {', '.join(risky[:6])}; anomaly max: {mx}.", remediation="Use parameterized queries and strict validation.", cwe="CWE-89", tags=["sqli"], references=["OWASP SQL Injection Prevention Cheat Sheet"]))
    if any(f["method"] == "get" for f in forms):
        out.append(Finding(title="Query-Exposed Input Workflow", category="SQL Injection", severity="medium", confidence=0.74, endpoint=target_url, description="GET forms increase review priority for search and filter endpoints.", impact="Query-driven workflows are common high-risk entry points.", evidence=f"Forms discovered: {len(forms)}.", remediation="Review search/filter handlers and enforce typed validation.", cwe="CWE-89", tags=["forms"], references=["OWASP Query Parameter Validation"]))
    if any("/api/" in p["url"] or p["url"].endswith(".json") for p in pages):
        out.append(Finding(title="API Surface Discovered", category="Security Misconfiguration", severity="low", confidence=0.81, endpoint=target_url, description="API-like routes were discovered during crawl.", impact="API endpoints can enlarge unaudited attack surface.", evidence="Detected /api/ or .json routes during crawl.", remediation="Review auth, validation, and rate limiting across APIs.", cwe="CWE-306", tags=["api"], references=["OWASP API Security Top 10"]))
    if any(p["url"].endswith("/robots.txt") and p["status"] == 200 for p in pages) or any("sitemap" in p["url"] and p["status"] == 200 for p in pages):
        out.append(Finding(title="Discovery Metadata Exposed", category="Security Misconfiguration", severity="info", confidence=0.8, endpoint=target_url, description="robots.txt or sitemap.xml was exposed.", impact="Discovery metadata can simplify route enumeration.", evidence="robots/sitemap observed during crawl.", remediation="Ensure discovery files do not disclose sensitive paths.", cwe="CWE-200", tags=["recon"], references=["OWASP Information Exposure guidance"]))
    for t in tech:
        if t.name in {"PHP", "ASP.NET", "WordPress"}:
            out.append(Finding(title=f"Technology Exposure: {t.name}", category="Security Misconfiguration", severity="low", confidence=t.confidence, endpoint=target_url, description=f"{t.name} markers were detected.", impact="Known stack identification can help targeted attacks.", evidence=t.evidence, remediation=t.hardening_advice, cwe="CWE-200", tags=["fingerprinting"], references=["OWASP Attack Surface Analysis Cheat Sheet"]))
    open_non_web = [p for p in ports if p.state == "open" and p.port not in {80, 443, 8080, 8443, 8000}]
    if open_non_web:
        out.append(Finding(title="Non-Web Ports Exposed", category="Security Misconfiguration", severity="medium", confidence=0.82, endpoint=target_url, description="Additional network services are reachable on the target host.", impact="Exposed non-web services can broaden attack surface and require separate hardening and access control review.", evidence="Open ports: " + ", ".join(f"{p.port}/{p.service_hint or 'unknown'}" for p in open_non_web[:8]), remediation="Restrict unnecessary services, apply host firewall rules, and validate authentication and patching for exposed services.", cwe="CWE-668", tags=["network", "ports"], references=["OWASP Attack Surface Analysis Cheat Sheet"]))
    return out


def _scan_ports(target_url: str, profile: ScanProfile) -> list[PortObservation]:
    host = urlparse(target_url).hostname
    if not host:
        return []
    selected = [80, 443, 8080] if profile == "quick" else [80, 443, 8080, 8443, 22, 3306, 5432] if profile == "balanced" else list(COMMON_PORTS.keys())
    results: list[PortObservation] = []
    for port in selected:
        state = "filtered"
        note = "No response"
        try:
            with socket.create_connection((host, port), timeout=0.6):
                state = "open"
                note = "TCP connection succeeded"
        except TimeoutError:
            state = "filtered"
            note = "Timed out"
        except OSError:
            state = "closed"
            note = "Connection refused or unreachable"
        results.append(PortObservation(port=port, state=state, service_hint=COMMON_PORTS.get(port), note=note))
    return results


def _merge_headers(pages: list[dict[str, Any]]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for p in pages:
        for k, v in p["headers"].items():
            merged.setdefault(k, v)
    return merged

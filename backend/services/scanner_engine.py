from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from models import (
    AssetRecord,
    Finding,
    LoginStep,
    PageRisk,
    ParameterObservation,
    PortObservation,
    RequestContext,
    ScanProfile,
    TechnologyFingerprint,
)

SUSPICIOUS_NAMES = {
    "id", "user", "username", "email", "search", "query",
    "q", "filter", "sort", "category", "page", "item", "product"
}

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


# =========================================================
# FIXED EXECUTE SCAN FUNCTION
# =========================================================
def execute_scan(
    target_url: str,
    profile: ScanProfile,
    context: RequestContext
) -> ScanExecutionResult:

    session = _build_session(context)

    pages = _crawl(target_url, session, profile)

    # FIX: Prevent crash when crawl returns empty
    if not pages:
        return ScanExecutionResult(
            engine="heuristic",
            findings=[
                Finding(
                    title="Target Unreachable",
                    category="Connection Error",
                    severity="high",
                    confidence=1.0,
                    endpoint=target_url,
                    description="Unable to reach or crawl target URL.",
                    impact="Scan could not proceed because target is unreachable.",
                    evidence="No pages were returned during crawl.",
                    remediation="Check target URL, SSL certificate, internet connectivity, or firewall restrictions.",
                    cwe="CWE-200",
                    tags=["connection"],
                    references=["Target URL unreachable"],
                )
            ],
            zap_session=None,
            technologies=[],
            risky_parameters=[],
            forms_discovered=0,
            get_forms=0,
            anomaly_observations=[],
            page_risk_map=[],
            assets=[],
            ports=[],
        )

    tech = _fingerprint(
        " ".join(p["body"] for p in pages),
        _merge_headers(pages)
    )

    forms = [f for p in pages for f in p["forms"]]

    risky = _discover_params(
        target_url,
        " ".join(p["body"] for p in pages),
        forms
    )

    anomalies = _compare(target_url, risky, session)
    assets = _assets_from_pages(pages, target_url)
    page_map = _page_map(pages)
    ports = _scan_ports(target_url, profile)

    findings = _findings(
        target_url,
        risky,
        forms,
        anomalies,
        tech,
        pages,
        ports
    )

    return ScanExecutionResult(
        engine="heuristic",
        findings=findings,
        zap_session=None,
        technologies=tech,
        risky_parameters=risky,
        forms_discovered=len(forms),
        get_forms=sum(1 for f in forms if f["method"] == "get"),
        anomaly_observations=anomalies,
        page_risk_map=page_map,
        assets=assets,
        ports=ports,
    )


# =========================================================
# SESSION BUILDER
# =========================================================
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

    elif (
        context.auth_mode == "form"
        and context.login_url
        and context.username
        and context.password
    ):
        data = {
            context.username_field: context.username,
            context.password_field: context.password,
            **context.extra_login_fields,
        }
        try:
            s.post(
                str(context.login_url),
                data=data,
                timeout=8,
                allow_redirects=True
            )
        except requests.RequestException:
            pass

    return s


def _login_step(
    session: requests.Session,
    step: LoginStep,
    context: RequestContext
) -> None:
    data = dict(step.static_fields)

    if step.username_field and (step.username_value or context.username):
        data[step.username_field] = step.username_value or context.username or ""

    if step.password_field and (step.password_value or context.password):
        data[step.password_field] = step.password_value or context.password or ""

    try:
        if step.method == "GET":
            session.get(
                str(step.url),
                params=data,
                headers=step.headers,
                timeout=8,
                allow_redirects=True
            )
        else:
            session.post(
                str(step.url),
                data=data,
                headers=step.headers,
                timeout=8,
                allow_redirects=True
            )
    except requests.RequestException:
        pass


# =========================================================
# HTML PARSER
# =========================================================
class _Parser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict[str, Any]] = []
        self.assets: list[dict[str, str]] = []
        self.links: list[str] = []
        self.active: dict[str, Any] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]]
    ) -> None:
        a = dict(attrs)

        if tag == "form":
            self.active = {
                "action": urljoin(
                    self.base_url,
                    a.get("action") or self.base_url
                ),
                "method": (a.get("method") or "get").lower(),
                "inputs": [],
            }

        elif tag in {"input", "textarea", "select"} and self.active is not None:
            if a.get("name"):
                self.active["inputs"].append({
                    "name": a["name"],
                    "type": (a.get("type") or tag).lower()
                })

        elif tag == "script" and a.get("src"):
            self.assets.append({
                "url": urljoin(self.base_url, a["src"]),
                "type": "script"
            })

        elif tag == "img" and a.get("src"):
            self.assets.append({
                "url": urljoin(self.base_url, a["src"]),
                "type": "image"
            })

        elif tag == "a" and a.get("href"):
            href = a["href"]
            if not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(urljoin(self.base_url, href))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self.active is not None:
            self.forms.append(self.active)
            self.active = None


# =========================================================
# CRAWLER
# =========================================================
def _crawl(
    target_url: str,
    session: requests.Session,
    profile: ScanProfile
) -> list[dict[str, Any]]:

    limit = 4 if profile == "quick" else 8 if profile == "balanced" else 12

    queue = [
        target_url,
        urljoin(target_url, "/robots.txt"),
        urljoin(target_url, "/sitemap.xml"),
    ]

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

            pages.append({
                "url": r.url,
                "status": r.status_code,
                "headers": {
                    k.lower(): v for k, v in r.headers.items()
                },
                "body": body,
                "forms": parser.forms,
                "assets": parser.assets,
            })

            for link in parser.links[:20]:
                if (
                    urlparse(link).netloc ==
                    urlparse(target_url).netloc
                    and link not in seen
                    and link not in queue
                ):
                    queue.append(link)

        except requests.RequestException:
            continue

    return pages


# =========================================================
# HELPER FUNCTIONS
# =========================================================
def _discover_params(target_url, body, forms):
    out = set(parse_qs(urlparse(target_url).query).keys())
    for form in forms:
        for field in form["inputs"]:
            n = field["name"].lower()
            if n in SUSPICIOUS_NAMES:
                out.add(field["name"])
    return sorted(out)


def _compare(target_url, params, session):
    return []


def _assets_from_pages(pages, target_url):
    return []


def _page_map(pages):
    return []


def _scan_ports(target_url, profile):
    return []


def _merge_headers(pages):
    merged = {}
    for p in pages:
        for k, v in p["headers"].items():
            merged.setdefault(k, v)
    return merged


def _fingerprint(body, headers):
    return []


def _findings(target_url, risky, forms, anomalies, tech, pages, ports):
    return []
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from models import AuthDiscoveryCandidate, AuthDiscoveryResponse

LIKELY_LOGIN_PATHS = ["/login", "/signin", "/sign-in", "/auth/login", "/account/login"]
USERNAME_NAMES = {"username", "email", "user", "login", "userid"}
PASSWORD_NAMES = {"password", "pass", "passwd"}
CSRF_NAMES = {"csrf", "_token", "csrfmiddlewaretoken", "__requestverificationtoken"}


class _DiscoveryParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[dict] = []
        self.links: list[str] = []
        self._active: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "form":
            self._active = {
                "action": urljoin(self.base_url, a.get("action") or self.base_url),
                "method": (a.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag == "input" and self._active is not None:
            self._active["inputs"].append(
                {
                    "name": a.get("name") or "",
                    "type": (a.get("type") or "text").lower(),
                    "value": a.get("value") or "",
                }
            )
        elif tag == "a" and a.get("href"):
            href = a["href"]
            if not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(urljoin(self.base_url, href))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._active is not None:
            self.forms.append(self._active)
            self._active = None


def discover_auth(target_url: str, headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None) -> AuthDiscoveryResponse:
    session = requests.Session()
    if headers:
        session.headers.update(headers)
    if cookies:
        session.cookies.update(cookies)

    host = urlparse(target_url).netloc
    queue = [target_url, *[urljoin(target_url, path) for path in LIKELY_LOGIN_PATHS]]
    seen: set[str] = set()
    candidates: list[AuthDiscoveryCandidate] = []

    while queue and len(seen) < 8:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            response = session.get(url, timeout=6, allow_redirects=True)
        except requests.RequestException:
            continue
        parser = _DiscoveryParser(response.url)
        parser.feed(response.text)
        for form in parser.forms:
            candidate = _candidate_from_form(form)
            if candidate is not None:
                candidates.append(candidate)
        for link in parser.links[:12]:
            if urlparse(link).netloc == host and any(path in link.lower() for path in ["login", "signin", "auth"]):
                queue.append(link)

    candidates = _dedupe_candidates(candidates)
    suggested = "form" if candidates else "bearer" if any("api" in target_url.lower() for _ in [0]) else "none"
    return AuthDiscoveryResponse(suggested_auth_type=suggested, candidates=candidates)


def _candidate_from_form(form: dict) -> AuthDiscoveryCandidate | None:
    username_field = None
    password_field = None
    csrf_fields: list[str] = []
    hidden_fields: dict[str, str] = {}

    for item in form["inputs"]:
        name = (item["name"] or "").lower()
        input_type = item["type"]
        if name in USERNAME_NAMES or input_type == "email":
            username_field = item["name"]
        if name in PASSWORD_NAMES or input_type == "password":
            password_field = item["name"]
        if any(token in name for token in CSRF_NAMES):
            csrf_fields.append(item["name"])
        if input_type == "hidden" and item["name"]:
            hidden_fields[item["name"]] = item["value"]

    if not username_field and not password_field:
        return None

    confidence = 0.55
    if username_field:
        confidence += 0.2
    if password_field:
        confidence += 0.2
    if form["method"] == "post":
        confidence += 0.05

    return AuthDiscoveryCandidate(
        login_url=form["action"],
        method=form["method"],
        username_field=username_field,
        password_field=password_field,
        csrf_fields=csrf_fields,
        hidden_fields=hidden_fields,
        confidence=min(confidence, 0.98),
    )


def _dedupe_candidates(candidates: list[AuthDiscoveryCandidate]) -> list[AuthDiscoveryCandidate]:
    seen: set[tuple[str, str, str | None, str | None]] = set()
    unique: list[AuthDiscoveryCandidate] = []
    for candidate in sorted(candidates, key=lambda item: item.confidence, reverse=True):
        key = (candidate.login_url, candidate.method, candidate.username_field, candidate.password_field)
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique[:6]

from __future__ import annotations

import asyncio
from typing import Any

import requests

from config import settings
from models import Finding, ScanProfile


class ZapOrchestrator:
    def __init__(self) -> None:
        self.base_url = settings.zap_api_url.rstrip("/")
        self.api_key = settings.zap_api_key

    def _params(self, **kwargs: Any) -> dict[str, Any]:
        params = dict(kwargs)
        if self.api_key:
            params["apikey"] = self.api_key
        return params

    def is_available(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/JSON/core/view/version/", timeout=3)
            return response.ok
        except requests.RequestException:
            return False

    async def run_scan(self, target_url: str, profile: ScanProfile) -> list[Finding]:
        spider_id = self._invoke("/JSON/spider/action/scan/", url=target_url).get("scan")
        if spider_id:
            await self._wait_for_status("/JSON/spider/view/status/", "status", spider_id)

        if profile in {"balanced", "deep"}:
            ascan_id = self._invoke("/JSON/ascan/action/scan/", url=target_url).get("scan")
            if ascan_id:
                await self._wait_for_status("/JSON/ascan/view/status/", "status", ascan_id)

        alerts = self._invoke("/JSON/core/view/alerts/", baseurl=target_url).get("alerts", [])
        return [self._normalize_alert(alert) for alert in alerts]

    def _invoke(self, path: str, **params: Any) -> dict[str, Any]:
        response = requests.get(f"{self.base_url}{path}", params=self._params(**params), timeout=20)
        response.raise_for_status()
        return response.json()

    async def _wait_for_status(self, path: str, field: str, scan_id: str) -> None:
        elapsed = 0.0
        while elapsed < settings.zap_max_wait_seconds:
            payload = self._invoke(path, scanId=scan_id)
            if int(payload.get(field, "0")) >= 100:
                return
            await asyncio.sleep(settings.zap_poll_seconds)
            elapsed += settings.zap_poll_seconds

    def _normalize_alert(self, alert: dict[str, Any]) -> Finding:
        severity = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info",
        }.get(alert.get("risk", "Low"), "low")
        category = alert.get("alert", "Security Misconfiguration")
        return Finding(
            title=alert.get("name", "ZAP Alert"),
            category=category,
            severity=severity,
            confidence=0.9,
            endpoint=alert.get("url", ""),
            description=alert.get("description", "OWASP ZAP reported a vulnerability indicator."),
            impact=alert.get("other", "Review application behavior and harden the affected endpoint."),
            evidence=alert.get("evidence", "No evidence provided."),
            remediation=alert.get("solution", "Review and remediate the affected endpoint."),
            cwe=f"CWE-{alert.get('cweid')}" if alert.get("cweid") else "CWE-0",
            tags=[tag for tag in [alert.get("confidence"), alert.get("pluginId")] if tag],
            source="zap",
        )

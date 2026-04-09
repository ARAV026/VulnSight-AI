from __future__ import annotations

import os
from typing import Any

import requests


class ZapClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/")
        self.api_key = os.getenv("ZAP_API_KEY", "")

    def is_available(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/JSON/core/view/version/", timeout=3)
            return response.ok
        except requests.RequestException:
            return False

    def start_spider(self, target_url: str) -> dict[str, Any]:
        params = {"url": target_url}
        if self.api_key:
            params["apikey"] = self.api_key
        response = requests.get(f"{self.base_url}/JSON/spider/action/scan/", params=params, timeout=10)
        response.raise_for_status()
        return response.json()

    def active_scan(self, target_url: str) -> dict[str, Any]:
        params = {"url": target_url}
        if self.api_key:
            params["apikey"] = self.api_key
        response = requests.get(f"{self.base_url}/JSON/ascan/action/scan/", params=params, timeout=10)
        response.raise_for_status()
        return response.json()

    def spider_status(self, scan_id: str) -> dict[str, Any]:
        params = {"scanId": scan_id}
        if self.api_key:
            params["apikey"] = self.api_key
        response = requests.get(f"{self.base_url}/JSON/spider/view/status/", params=params, timeout=10)
        response.raise_for_status()
        return response.json()

    def active_scan_status(self, scan_id: str) -> dict[str, Any]:
        params = {"scanId": scan_id}
        if self.api_key:
            params["apikey"] = self.api_key
        response = requests.get(f"{self.base_url}/JSON/ascan/view/status/", params=params, timeout=10)
        response.raise_for_status()
        return response.json()

    def alerts(self, target_url: str) -> dict[str, Any]:
        params = {"baseurl": target_url}
        if self.api_key:
            params["apikey"] = self.api_key
        response = requests.get(f"{self.base_url}/JSON/core/view/alerts/", params=params, timeout=10)
        response.raise_for_status()
        return response.json()

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import joblib
except Exception:  # pragma: no cover
    joblib = None


SQLI_MARKERS = ["select ", "union ", "sleep(", "or 1=1", "information_schema", "database error", "sql syntax"]
XSS_MARKERS = ["<script", "javascript:", "onerror=", "onload=", "alert("]
CSRF_MARKERS = ["csrf", "_token", "csrfmiddlewaretoken", "__requestverificationtoken"]


@dataclass
class HybridDecision:
    category: str
    confidence: float
    source: str
    notes: list[str]


class HybridDetector:
    def __init__(self, model_dir: str | Path | None = None) -> None:
        self.model_dir = Path(model_dir) if model_dir else Path(__file__).with_name("artifacts")
        self.rf = self._load("random_forest.joblib")
        self.gb = self._load("gradient_boosting.joblib")
        self.iforest = self._load("isolation_forest.joblib")

    def _load(self, filename: str):  # noqa: ANN001, ANN201
        if joblib is None:
            return None
        path = self.model_dir / filename
        if not path.exists():
            return None
        try:
            return joblib.load(path)
        except Exception:
            return None

    def evaluate(self, text: str, context: dict[str, Any] | None = None) -> list[HybridDecision]:
        context = context or {}
        lowered = text.lower()
        notes: list[str] = []
        decisions: list[HybridDecision] = []

        if any(marker in lowered for marker in SQLI_MARKERS):
            notes.append("Matched rule-based SQLi markers")
            decisions.append(HybridDecision("SQL Injection", 0.9, "rules", notes.copy()))
        if any(marker in lowered for marker in XSS_MARKERS):
            decisions.append(HybridDecision("Cross-Site Scripting", 0.88, "rules", ["Matched rule-based XSS markers"]))
        if context.get("forms_discovered", 0) and not context.get("csrf_present", False):
            decisions.append(HybridDecision("CSRF", 0.86, "rules", ["Form workflow lacks visible CSRF token markers"]))

        ensemble = self._ensemble_score(lowered)
        if ensemble["anomaly"] >= 0.85 and not decisions:
            decisions.append(HybridDecision("Anomalous Behavior", ensemble["anomaly"], "ensemble", ["Ensemble anomaly score exceeded threshold"]))

        if context.get("sequence_risk", 0) > 0.7:
            decisions.append(HybridDecision("Session Flow Risk", 0.87, "context", ["Unusual request or session sequence observed"]))

        return decisions

    def _ensemble_score(self, text: str) -> dict[str, float]:
        length_signal = min(1.0, len(text) / 1000)
        scores = {
            "random_forest": 0.0,
            "gradient_boosting": 0.0,
            "anomaly": length_signal * 0.25,
        }
        if self.rf is not None and hasattr(self.rf, "predict_proba"):
            try:
                scores["random_forest"] = float(max(self.rf.predict_proba([text])[0]))
            except Exception:
                pass
        if self.gb is not None and hasattr(self.gb, "predict_proba"):
            try:
                scores["gradient_boosting"] = float(max(self.gb.predict_proba([text])[0]))
            except Exception:
                pass
        if self.iforest is not None and hasattr(self.iforest, "decision_function"):
            try:
                value = float(self.iforest.decision_function([[len(text), text.count("="), text.count("&")]])[0])
                scores["anomaly"] = max(scores["anomaly"], min(1.0, 1 - value))
            except Exception:
                pass
        return scores

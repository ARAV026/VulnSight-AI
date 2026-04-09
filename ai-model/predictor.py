from __future__ import annotations

from pathlib import Path

import joblib


class SeverityPredictor:
    def __init__(self, model_path: str = "severity_model.joblib") -> None:
        self.model_path = Path(model_path)
        self.model = joblib.load(self.model_path) if self.model_path.exists() else None

    def predict(self, text: str) -> str:
        if self.model is None:
            return "medium"
        return str(self.model.predict([text])[0])

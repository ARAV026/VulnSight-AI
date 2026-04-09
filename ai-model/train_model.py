from __future__ import annotations

from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

TRAINING_DATA = [
    ("database error near quote injection parameter union select", "high"),
    ("reflected javascript alert payload in query", "medium"),
    ("csrf token missing on transfer form", "medium"),
    ("cookie missing httponly secure", "medium"),
    ("no content security policy header", "low"),
    ("x-frame-options header absent", "low"),
    ("admin takeover remote code execution", "critical"),
    ("verbose server banner exposed", "info"),
]


def train_and_save_model(output_path: str = "severity_model.joblib") -> str:
    texts = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
            ("clf", LogisticRegression(max_iter=200)),
        ]
    )
    pipeline.fit(texts, labels)
    joblib.dump(pipeline, output_path)
    return str(Path(output_path).resolve())


if __name__ == "__main__":
    path = train_and_save_model()
    print(f"Saved severity model to {path}")

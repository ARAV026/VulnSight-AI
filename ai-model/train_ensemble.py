from __future__ import annotations

from pathlib import Path

import joblib
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline

DATA = [
    ("union select username,password from users", "SQL Injection"),
    ("database syntax error near select", "SQL Injection"),
    ("<script>alert(1)</script>", "Cross-Site Scripting"),
    ("javascript:onerror=alert(1)", "Cross-Site Scripting"),
    ("form submission without csrf token", "CSRF"),
    ("normal landing page with hero banner", "Benign"),
    ("search query with sort filter category", "Benign"),
    ("unexpected sequence across privileged endpoints", "Anomalous Behavior"),
]


def train(output_dir: str = "artifacts") -> str:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    texts = [item[0] for item in DATA]
    labels = [item[1] for item in DATA]

    rf = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2))), ("clf", RandomForestClassifier(n_estimators=100, random_state=42))])
    gb = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2))), ("clf", GradientBoostingClassifier(random_state=42))])
    rf.fit(texts, labels)
    gb.fit(texts, labels)
    joblib.dump(rf, out / "random_forest.joblib")
    joblib.dump(gb, out / "gradient_boosting.joblib")

    anomaly_samples = [[len(text), text.count("="), text.count("&")] for text in texts]
    iforest = IsolationForest(random_state=42, contamination=0.2)
    iforest.fit(anomaly_samples)
    joblib.dump(iforest, out / "isolation_forest.joblib")
    return str(out.resolve())


if __name__ == "__main__":
    print(train())

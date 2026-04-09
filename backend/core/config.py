from __future__ import annotations

import os


class Settings:
    app_name = "VulnSight AI"
    app_version = "2.0.0"
    jwt_secret = os.getenv("JWT_SECRET", "change-me-for-production")
    jwt_algorithm = "HS256"
    access_token_expire_minutes = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))
    mongo_uri = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017")
    mongo_db = os.getenv("MONGO_DB", "vulnsight_ai")
    zap_api_url = os.getenv("ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/")
    zap_api_key = os.getenv("ZAP_API_KEY", "")


settings = Settings()

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "VulnSight AI"
    app_version: str = "2.0.0"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    mongodb_uri: str = "mongodb://127.0.0.1:27017"
    mongodb_database: str = "vulnsight"
    jwt_secret: str = "change-this-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 12
    zap_api_url: str = "http://127.0.0.1:8080"
    zap_api_key: str = ""
    zap_poll_seconds: float = 2.0
    zap_max_wait_seconds: int = 300

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()


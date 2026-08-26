"""Application configuration loaded from environment variables (prefix: RECONPULSE_)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RECONPULSE_", env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+psycopg2://reconpulse:reconpulse@localhost:5432/reconpulse"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: str = "http://localhost:5173,http://localhost:8080"

    # Worker
    worker_poll_interval: float = 2.0
    tool_timeout: float = 300.0          # hard timeout per external tool execution (seconds)
    http_probe_timeout: float = 10.0
    dns_timeout: float = 5.0
    max_output_bytes: int = 20_000_000   # cap on captured external tool output
    max_concurrent_requests: int = 10    # per-adapter concurrency for HTTP probing

    # Logging
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    # Persistence
    database_url: str = "postgresql+psycopg://zombieshield:zombieshield@db:5432/zombieshield"
    backend_cors_origins: str = "http://localhost:5173,http://localhost:8080"

    # Platform security
    jwt_secret: str = "insecure-development-secret-change-me-in-dotenv-file"
    jwt_expire_minutes: int = 480
    admin_username: str = "admin"
    admin_password: str = "zombieshield-admin"
    analyst_username: str = "analyst"
    analyst_password: str = "zombieshield-analyst"
    auth_disabled: bool = False  # tests and local experiments only

    # Discovery
    discovery_git_root: str = "./discovery-repositories"
    lab_config_path: str = ""  # YAML describing the evidence sources to seed
    log_follow_interval_seconds: float = 5.0
    log_follow_enabled: bool = True

    # Lifecycle / analytics
    lifecycle_activity_window_days: int = 30
    anomaly_window_seconds: int = 60
    client_hash_salt: str = "zombieshield-lab-salt"

    # Threat intelligence
    threat_intel_mode: str = "auto"  # online | offline | auto (online, falling back to cache)
    threat_cache_dir: str = str(BACKEND_ROOT / "data" / "threat_cache")
    osv_api_url: str = "https://api.osv.dev/v1"
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    epss_api_url: str = "https://api.first.org/data/v1/epss"

    # Machine learning
    ml_artifacts_dir: str = str(BACKEND_ROOT / "ml_artifacts")

    # Gateway (read by team-implemented stages)
    gateway_rules_dir: str = "./gateway-rules"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

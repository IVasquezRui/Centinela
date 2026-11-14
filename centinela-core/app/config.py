from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://centinela_app:change-me-in-dev@localhost:5432/centinela"

    target_gov_pago_url: str = "http://gov-pago:80"
    target_tickets_url: str = "http://tickets:4000"

    deepseek_api_key: str = ""
    deepseek_api_base: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    ai_timeout_seconds: float = 3.0

    blocklist_threshold: int = 3
    blocklist_window_seconds: int = 60
    blocklist_quarantine_seconds: int = 300

    queue_batch_size: int = 50
    queue_flush_interval_seconds: float = 0.5


@lru_cache
def get_settings() -> Settings:
    return Settings()

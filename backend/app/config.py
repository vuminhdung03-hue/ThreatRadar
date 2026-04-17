from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql://localhost/threatradar"
    redis_url: str = "redis://localhost:6379/0"
    nvd_api_key: str = ""
    secret_key: str = "dev-secret-key-change-in-prod"
    environment: str = "development"

    @computed_field
    @property
    def async_database_url(self) -> str:
        """Convert sync postgres URL to asyncpg URL for SQLAlchemy async engine."""
        url = self.database_url
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url


settings = Settings()

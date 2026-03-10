from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    """
    Centralized application configuration.
    Loads values from .env file and environment variables.
    """

    # =====================================================
    # Application Settings
    # =====================================================
    APP_NAME: str = "SAMHM Backend API"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"  # development | production

    # =====================================================
    # Security Settings
    # =====================================================
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Privacy-by-Design Salt (used for hashing text)
    TEXT_HASH_SALT: str

    # =====================================================
    # Rate Limiting
    # =====================================================
    RATE_LIMIT_PER_MINUTE: int = 60

    # =====================================================
    # Database
    # =====================================================
    DATABASE_URL: str = "postgresql+psycopg://samhm:samhm_password@localhost:5432/samhm"
    DB_ECHO: bool = False
    DB_AUTO_CREATE: bool = True
    DEFAULT_ADMIN_EMAIL: str = "admin@samhm.local"
    DEFAULT_ADMIN_PASSWORD: str = "Admin123!"
    DEFAULT_ADMIN_NAME: str = "System Administrator"

    # =====================================================
    # CORS Configuration
    # =====================================================
    FRONTEND_URL: str = "http://localhost:3000"

    # =====================================================
    # Model Runtime
    # =====================================================
    MODEL_DIR: str = "app/models"
    MODEL_FILE: str | None = None
    MODEL_METADATA_FILE: str | None = None
    MODEL_LABELS_FILE: str | None = None
    MODEL_NAME: str = "sentiment_service"
    MODEL_VERSION_OVERRIDE: str | None = None

    # =====================================================
    # Host Security  ✅ FIXED
    # =====================================================
    # Used by TrustedHostMiddleware
    allowed_hosts: List[str] = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "172.19.0.1",
        "172.19.0.3",
        "*",
    ]

    # =====================================================
    # Pydantic Settings Config
    # =====================================================
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    # =====================================================
    # Helper Properties
    # =====================================================
    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def allowed_origins(self) -> List[str]:
        """
        Dynamic CORS origins.
        In production you can restrict this.
        """
        if self.is_production:
            return [self.FRONTEND_URL]
        return ["*"]


# =====================================================
# Cached settings instance (Best Practice)
# =====================================================
@lru_cache()
def get_settings() -> Settings:
    return Settings()


# =====================================================
# Global settings instance
# =====================================================
settings = get_settings()

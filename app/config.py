from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # Application
    app_name: str = "Identity Service"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Database
    database_url: str = (
        "postgresql+asyncpg://identity_user:identity_pass@localhost:5432/identity_db"
    )
    db_echo: bool = False

    # Security
    secret_key: str = "dev-secret"
    algorithm: str = ""
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # CORS
    allowed_origins: List[str] = ["http://localhost:3000"]

    # OAuth - Google
    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""

    # OAuth - Kakao
    kakao_client_id: str = ""
    kakao_client_secret: str = ""
    kakao_redirect_uri: str = ""

    # OAuth - Naver
    naver_client_id: str = ""
    naver_client_secret: str = ""
    naver_redirect_uri: str = ""

    # Email
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""

    # SMS
    sms_api_key: str = ""
    sms_api_secret: str = ""
    sms_sender: str = ""

    # Redis
    redis_url: str = "redis://localhost:6379/0"


settings = Settings()

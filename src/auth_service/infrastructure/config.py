"""Application settings, read from environment variables or ``.env``."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration of the API.

    Every attribute maps to the environment variable of the same name in
    upper case; the connection string and the JWT settings use the
    ``AUTH_`` prefix through their aliases (for example, ``database_url``
    comes from ``AUTH_DATABASE_URL``).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    environment: Literal["development", "production"] = "development"
    application_name: str = "SynapseAI"
    database_url: SecretStr = Field(alias="AUTH_DATABASE_URL")
    jwt_private_key: SecretStr = Field(alias="AUTH_JWT_PRIVATE_KEY")
    jwt_key_id: str = Field(default="auth-key-1", alias="AUTH_JWT_KEY_ID")
    jwt_issuer: str = Field(default="auth-service", alias="AUTH_JWT_ISSUER")
    jwt_audience: str = Field(
        default="synapse-apps",
        alias="AUTH_JWT_AUDIENCE",
    )
    access_token_ttl_minutes: int = Field(default=15, gt=0)
    refresh_token_ttl_hours: int = Field(default=12, gt=0)
    keep_signed_in_ttl_days: int = Field(default=30, gt=0)
    password_reset_ttl_minutes: int = Field(default=30, gt=0)
    password_reset_url: str = "http://localhost:5500/reset-password.html"
    login_max_failed_attempts: int = Field(default=5, gt=0)
    login_throttle_window_minutes: int = Field(default=15, gt=0)
    cors_allowed_origins: str = ""
    email_backend: Literal["console", "smtp", "resend"] = "console"
    resend_api_key: SecretStr | None = None
    resend_from: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_sender: str | None = None
    smtp_use_tls: bool = True

    @property
    def jwt_private_key_pem(self) -> str:
        """Return the signing key in PEM format.

        Environment variables that cannot hold line breaks may carry the
        key with literal ``\\n`` sequences; they are converted back.

        Returns
        -------
        str
            RSA private key in PEM format.
        """
        return self.jwt_private_key.get_secret_value().replace("\\n", "\n")

    @property
    def cors_origins(self) -> list[str]:
        """Split the comma-separated list of allowed CORS origins.

        Returns
        -------
        list[str]
            Allowed origins, without blanks.
        """
        return [
            origin.strip()
            for origin in self.cors_allowed_origins.split(",")
            if origin.strip()
        ]


@lru_cache
def get_settings() -> Settings:
    """Load the settings once per process.

    Returns
    -------
    Settings
        Cached settings instance.
    """
    return Settings()

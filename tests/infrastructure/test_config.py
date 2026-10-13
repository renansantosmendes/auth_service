"""Tests of the application settings."""

import pytest
from pydantic import ValidationError

from auth_service.infrastructure.config import Settings
from tests.credentials import (
    JWT_PRIVATE_KEY,
)


def test_settings_read_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Variables are read from the environment with defaults.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Sets environment variables.

    Returns
    -------
    None
    """
    monkeypatch.setenv("AUTH_DATABASE_URL", "postgresql://db/test")
    monkeypatch.setenv(
        "AUTH_JWT_PRIVATE_KEY",
        JWT_PRIVATE_KEY.replace("\n", "\\n"),
    )
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        "https://a.edu, ,https://b.edu",
    )
    settings = Settings(_env_file=None)
    assert settings.database_url.get_secret_value() == "postgresql://db/test"
    assert settings.access_token_ttl_minutes == 15
    assert settings.cors_origins == ["https://a.edu", "https://b.edu"]
    assert settings.jwt_private_key_pem == JWT_PRIVATE_KEY
    assert settings.jwt_audience == "synapse-apps"
    assert "PRIVATE KEY" not in repr(settings)


def test_settings_require_database_and_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing mandatory variables fail at start-up.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Removes environment variables.

    Returns
    -------
    None
    """
    monkeypatch.delenv("AUTH_DATABASE_URL", raising=False)
    monkeypatch.delenv("AUTH_JWT_PRIVATE_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)

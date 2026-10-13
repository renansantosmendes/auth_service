"""Tests of the administrative command line tools."""

from datetime import timedelta
from pathlib import Path

import pytest

import manage
from auth_service.cli import apply_schema, create_user, generate_signing_key
from auth_service.domain.exceptions import (
    EmailAlreadyRegisteredError,
    WeakPasswordError,
)
from auth_service.infrastructure.security.jwt_access_token_service import (
    JwtAccessTokenService,
)
from tests.credentials import NEW_PASSWORD
from tests.fakes import FakePasswordHasher, InMemoryUnitOfWork


def test_application_url_keeps_host_and_options() -> None:
    """Only the credentials of the owner URL are replaced."""
    url = apply_schema.build_application_url(
        "postgresql://owner:secret@host-pooler.neon.tech/db?sslmode=require",
        "p@ss/word",
    )
    assert url == (
        "postgresql://identity_app:p%40ss%2Fword@host-pooler.neon.tech/db"
        "?sslmode=require"
    )


def test_write_env_variable_replaces_or_appends(tmp_path: Path) -> None:
    """Existing variables are replaced and new ones appended.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory.

    Returns
    -------
    None
    """
    env_path = tmp_path / ".env"
    env_path.write_text("A=1\nAUTH_DATABASE_URL=old\n", encoding="utf-8")
    apply_schema.write_env_variable(env_path, "AUTH_DATABASE_URL", "new")
    apply_schema.write_env_variable(env_path, "B", "2")
    assert env_path.read_text(encoding="utf-8") == (
        'A=1\nAUTH_DATABASE_URL="new"\nB="2"\n'
    )


def test_apply_schema_requires_owner_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Without ``NEON_DATABASE_URL`` the command stops with an error.

    Parameters
    ----------
    tmp_path : Path
        Temporary directory.
    monkeypatch : pytest.MonkeyPatch
        Points the command at an empty ``.env``.
    capsys : pytest.CaptureFixture
        Captures the output.

    Returns
    -------
    None
    """
    monkeypatch.setattr(apply_schema, "ENV_PATH", tmp_path / ".env")
    assert apply_schema.main([]) == 1
    assert "NEON_DATABASE_URL" in capsys.readouterr().out


def test_schema_file_is_found() -> None:
    """The command reads ``db/schema.sql`` from the project root."""
    assert "CREATE SCHEMA IF NOT EXISTS identity" in (
        apply_schema.SCHEMA_PATH.read_text(encoding="utf-8")
    )


def test_create_user_hashes_password(
    unit_of_work: InMemoryUnitOfWork,
) -> None:
    """The initial password is validated and stored hashed.

    Parameters
    ----------
    unit_of_work : InMemoryUnitOfWork
        In-memory unit of work.

    Returns
    -------
    None
    """
    user = create_user.create_user(
        unit_of_work=unit_of_work,
        password_hasher=FakePasswordHasher(),
        email=" ana@example.com ",
        full_name="Ana Lima",
        password=NEW_PASSWORD,
    )
    assert user.email == "ana@example.com"
    assert user.password_hash == f"hashed:{NEW_PASSWORD}"
    assert unit_of_work.commits == 1


def test_create_user_without_password(
    unit_of_work: InMemoryUnitOfWork,
) -> None:
    """Accounts may start without a password.

    Parameters
    ----------
    unit_of_work : InMemoryUnitOfWork
        In-memory unit of work.

    Returns
    -------
    None
    """
    user = create_user.create_user(
        unit_of_work=unit_of_work,
        password_hasher=FakePasswordHasher(),
        email="ana@example.com",
        full_name="Ana Lima",
        password=None,
    )
    assert user.password_hash is None
    assert not user.can_sign_in_with_password


def test_create_user_rejects_weak_password_and_duplicates(
    unit_of_work: InMemoryUnitOfWork,
) -> None:
    """Weak passwords and duplicated e-mails are refused.

    Parameters
    ----------
    unit_of_work : InMemoryUnitOfWork
        In-memory unit of work.

    Returns
    -------
    None
    """
    with pytest.raises(WeakPasswordError):
        create_user.create_user(
            unit_of_work=unit_of_work,
            password_hasher=FakePasswordHasher(),
            email="ana@example.com",
            full_name="Ana Lima",
            password="short",
        )
    create_user.create_user(
        unit_of_work=unit_of_work,
        password_hasher=FakePasswordHasher(),
        email="ana@example.com",
        full_name="Ana Lima",
        password=None,
    )
    with pytest.raises(EmailAlreadyRegisteredError):
        create_user.create_user(
            unit_of_work=unit_of_work,
            password_hasher=FakePasswordHasher(),
            email="ANA@example.com",
            full_name="Ana Lima",
            password=None,
        )


def test_read_new_password_requires_confirmation() -> None:
    """Both hidden entries must match."""
    matching = iter([NEW_PASSWORD, NEW_PASSWORD])
    different = iter([NEW_PASSWORD, "other"])
    assert create_user.read_new_password(
        lambda _prompt: next(matching)
    ) == NEW_PASSWORD
    assert create_user.read_new_password(
        lambda _prompt: next(different)
    ) is None


def test_generated_key_signs_tokens() -> None:
    """The generated key is accepted by the token service."""
    pem = generate_signing_key.generate_private_key_pem(key_size=2048)
    single_line = generate_signing_key.to_single_line(pem)
    assert "\n" not in single_line
    JwtAccessTokenService(
        private_key_pem=single_line.replace("\\n", "\n"),
        key_id="k",
        time_to_live=timedelta(minutes=1),
        issuer="auth-service",
        audience="synapse-apps",
    )


def test_generate_signing_key_prints_env_line(
    capsys: pytest.CaptureFixture,
) -> None:
    """The command prints a ready-to-paste ``.env`` line.

    Parameters
    ----------
    capsys : pytest.CaptureFixture
        Captures the output.

    Returns
    -------
    None
    """
    assert generate_signing_key.main(["--bits", "2048"]) == 0
    assert capsys.readouterr().out.startswith(
        'AUTH_JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n'
    )


def test_manage_rejects_unknown_command(
    capsys: pytest.CaptureFixture,
) -> None:
    """Unknown commands print the usage and fail.

    Parameters
    ----------
    capsys : pytest.CaptureFixture
        Captures the output.

    Returns
    -------
    None
    """
    assert manage.run(["unknown"]) == 1
    assert "create-user" in capsys.readouterr().out


def test_manage_dispatches_to_command(
    capsys: pytest.CaptureFixture,
) -> None:
    """Known commands run their module.

    Parameters
    ----------
    capsys : pytest.CaptureFixture
        Captures the output.

    Returns
    -------
    None
    """
    assert manage.run(["generate-signing-key", "--bits", "2048"]) == 0
    assert "AUTH_JWT_PRIVATE_KEY" in capsys.readouterr().out

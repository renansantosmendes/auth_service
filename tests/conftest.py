"""Shared fixtures of the test suite."""

from datetime import timedelta

import pytest

from auth_service.application.policies import SessionPolicy
from auth_service.application.services.session_token_issuer import (
    SessionTokenIssuer,
)
from auth_service.infrastructure.security.jwt_access_token_service import (
    JwtAccessTokenService,
)
from auth_service.infrastructure.security.opaque_token_generator import (
    SecretsOpaqueTokenGenerator,
)
from tests.fakes import FakeClock, FakePasswordHasher, InMemoryUnitOfWork
from tests.credentials import (
    JWT_PRIVATE_KEY,
)


@pytest.fixture
def clock() -> FakeClock:
    """Provide a frozen clock.

    Returns
    -------
    FakeClock
        Clock at the default moment.
    """
    return FakeClock()


@pytest.fixture
def unit_of_work(clock: FakeClock) -> InMemoryUnitOfWork:
    """Provide an in-memory unit of work.

    Parameters
    ----------
    clock : FakeClock
        Clock shared with the repositories.

    Returns
    -------
    InMemoryUnitOfWork
        Empty unit of work.
    """
    return InMemoryUnitOfWork(clock)


@pytest.fixture
def password_hasher() -> FakePasswordHasher:
    """Provide the fake password hasher.

    Returns
    -------
    FakePasswordHasher
        Instant hasher.
    """
    return FakePasswordHasher()


@pytest.fixture
def token_generator() -> SecretsOpaqueTokenGenerator:
    """Provide the real opaque token generator.

    Returns
    -------
    SecretsOpaqueTokenGenerator
        Token generator.
    """
    return SecretsOpaqueTokenGenerator()


@pytest.fixture
def access_token_service() -> JwtAccessTokenService:
    """Provide a JWT service with a test secret.

    Returns
    -------
    JwtAccessTokenService
        Service issuing 15-minute tokens.
    """
    return JwtAccessTokenService(
        private_key_pem=JWT_PRIVATE_KEY,
        key_id="test-key",
        time_to_live=timedelta(minutes=15),
        issuer="auth-service",
        audience="synapse-apps",
    )


@pytest.fixture
def session_token_issuer(
    access_token_service: JwtAccessTokenService,
    token_generator: SecretsOpaqueTokenGenerator,
) -> SessionTokenIssuer:
    """Provide a session token issuer with default lifetimes.

    Parameters
    ----------
    access_token_service : JwtAccessTokenService
        Access token service.
    token_generator : SecretsOpaqueTokenGenerator
        Refresh token generator.

    Returns
    -------
    SessionTokenIssuer
        Issuer with 12-hour and 30-day refresh lifetimes.
    """
    return SessionTokenIssuer(
        access_token_service=access_token_service,
        token_generator=token_generator,
        session_policy=SessionPolicy(),
    )

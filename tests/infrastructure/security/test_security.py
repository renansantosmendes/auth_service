"""Tests of the password hasher and the token implementations."""

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import RSAAlgorithm
from jwt.utils import base64url_encode

from auth_service.domain.exceptions import InvalidAccessTokenError
from auth_service.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)
from auth_service.infrastructure.security.jwt_access_token_service import (
    JwtAccessTokenService,
)
from auth_service.infrastructure.security.opaque_token_generator import (
    SecretsOpaqueTokenGenerator,
)
from tests.credentials import (
    JWT_PRIVATE_KEY,
    OTHER_JWT_PRIVATE_KEY,
    VALID_PASSWORD,
)
from tests.fakes import make_user


@pytest.fixture(scope="module")
def hasher() -> Argon2PasswordHasher:
    """Provide a cheap Argon2 hasher for fast tests.

    Returns
    -------
    Argon2PasswordHasher
        Hasher with minimal cost parameters.
    """
    return Argon2PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def test_argon2_hash_verifies_only_the_right_password(
    hasher: Argon2PasswordHasher,
) -> None:
    """Hashes are salted Argon2id and match only their password.

    Parameters
    ----------
    hasher : Argon2PasswordHasher
        Hasher under test.

    Returns
    -------
    None
    """
    password_hash = hasher.hash(VALID_PASSWORD)
    assert password_hash.startswith("$argon2id$")
    assert password_hash != hasher.hash(VALID_PASSWORD)
    assert hasher.verify(password_hash, VALID_PASSWORD)
    assert not hasher.verify(password_hash, "planejamento2026")


def test_argon2_handles_malformed_hash(
    hasher: Argon2PasswordHasher,
) -> None:
    """Malformed hashes never match and are flagged for rehash.

    Parameters
    ----------
    hasher : Argon2PasswordHasher
        Hasher under test.

    Returns
    -------
    None
    """
    assert not hasher.verify("not-a-hash", "anything")
    assert hasher.needs_rehash("not-a-hash")


def test_argon2_detects_outdated_parameters(
    hasher: Argon2PasswordHasher,
) -> None:
    """Hashes made with other parameters need a rehash.

    Parameters
    ----------
    hasher : Argon2PasswordHasher
        Hasher under test.

    Returns
    -------
    None
    """
    stronger = Argon2PasswordHasher(time_cost=2, memory_cost=8, parallelism=1)
    assert stronger.needs_rehash(hasher.hash(VALID_PASSWORD))
    assert not hasher.needs_rehash(hasher.hash(VALID_PASSWORD))
    hasher.simulate_verification("whatever")


ISSUER = "auth-service"
AUDIENCE = "synapse-apps"


def build_service(
    time_to_live: timedelta = timedelta(minutes=15),
) -> JwtAccessTokenService:
    """Create a JWT service with the test signing key.

    Parameters
    ----------
    time_to_live : timedelta
        Token lifetime.

    Returns
    -------
    JwtAccessTokenService
        Service under test.
    """
    return JwtAccessTokenService(
        private_key_pem=JWT_PRIVATE_KEY,
        key_id="test-key",
        time_to_live=time_to_live,
        issuer=ISSUER,
        audience=AUDIENCE,
    )


def build_claims(
    token_type: str = "access",
    audience: str = AUDIENCE,
) -> dict:
    """Build a valid-looking claim set for hand-made tokens.

    Parameters
    ----------
    token_type : str
        Value of the ``typ`` claim.
    audience : str
        Value of the ``aud`` claim.

    Returns
    -------
    dict
        JWT claims.
    """
    now = datetime.now(UTC)
    return {
        "sub": str(uuid4()),
        "sid": str(uuid4()),
        "typ": token_type,
        "iss": ISSUER,
        "aud": audience,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }


def test_jwt_round_trip_carries_identity_claims() -> None:
    """Issued tokens decode to the same user and session."""
    user, session_id = make_user(), uuid4()
    issued_at = datetime.now(UTC)
    issued = build_service().issue(user, session_id, issued_at)
    assert issued.expires_at == issued_at + timedelta(minutes=15)
    claims = build_service().decode(issued.token)
    assert (claims.user_id, claims.session_id) == (user.id, session_id)
    payload = jwt.decode(issued.token, options={"verify_signature": False})
    assert payload["email"] == user.email
    assert payload["name"] == user.full_name
    assert jwt.get_unverified_header(issued.token)["kid"] == "test-key"


def test_jwt_rejects_expired_token() -> None:
    """Tokens past their lifetime are refused."""
    issued = build_service().issue(
        make_user(),
        uuid4(),
        datetime.now(UTC) - timedelta(hours=1),
    )
    with pytest.raises(InvalidAccessTokenError):
        build_service().decode(issued.token)


@pytest.mark.parametrize(
    ("claims", "key", "algorithm"),
    [
        (build_claims(), OTHER_JWT_PRIVATE_KEY, "RS256"),
        (build_claims(token_type="refresh"), JWT_PRIVATE_KEY, "RS256"),
        (build_claims(audience="other-app"), JWT_PRIVATE_KEY, "RS256"),
    ],
)
def test_jwt_rejects_foreign_wrong_type_or_wrong_audience(
    claims: dict,
    key: str,
    algorithm: str,
) -> None:
    """Other signers, non-access tokens and other audiences are refused.

    Parameters
    ----------
    claims : dict
        Claims of the hand-made token.
    key : str
        Signing key.
    algorithm : str
        Signing algorithm.

    Returns
    -------
    None
    """
    token = jwt.encode(claims, key, algorithm=algorithm)
    with pytest.raises(InvalidAccessTokenError):
        build_service().decode(token)


def test_jwt_rejects_hs256_token_signed_with_public_key() -> None:
    """Algorithm confusion with the published public key is refused."""
    public_jwk = build_service().public_key_set()["keys"][0]
    public_pem = RSAAlgorithm.from_jwk(public_jwk).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    claims = {
        key: int(value.timestamp()) if isinstance(value, datetime) else value
        for key, value in build_claims().items()
    }
    header = {"alg": "HS256", "typ": "JWT", "kid": "test-key"}
    signing_input = ".".join(
        base64url_encode(json.dumps(part).encode("utf-8")).decode("ascii")
        for part in (header, claims)
    )
    signature = hmac.new(
        public_pem,
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    forged = f"{signing_input}.{base64url_encode(signature).decode('ascii')}"
    with pytest.raises(InvalidAccessTokenError):
        build_service().decode(forged)


def test_jwks_verifies_issued_tokens() -> None:
    """A client holding only the JWKS can verify the tokens."""
    service = build_service()
    issued = service.issue(make_user(), uuid4(), datetime.now(UTC))
    key_set = service.public_key_set()
    public_jwk = key_set["keys"][0]
    assert public_jwk["kid"] == "test-key"
    assert public_jwk["alg"] == "RS256"
    assert "d" not in public_jwk
    payload = jwt.decode(
        issued.token,
        jwt.PyJWK(public_jwk).key,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
    )
    assert payload["typ"] == "access"


def test_service_rejects_non_rsa_signing_key() -> None:
    """Only RSA keys can sign the tokens."""
    elliptic_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError):
        JwtAccessTokenService(
            private_key_pem=elliptic_key.decode("ascii"),
            key_id="k",
            time_to_live=timedelta(minutes=1),
            issuer=ISSUER,
            audience=AUDIENCE,
        )


def test_opaque_tokens_are_random_and_hash_deterministically() -> None:
    """Tokens differ every time; their hash is a stable SHA-256."""
    generator = SecretsOpaqueTokenGenerator()
    first, second = generator.generate(), generator.generate()
    assert first != second
    assert len(first) >= 64
    assert generator.hash(first) == generator.hash(first)
    assert len(generator.hash(first)) == 64

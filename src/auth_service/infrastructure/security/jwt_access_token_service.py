"""Access tokens encoded as RS256-signed JSON Web Tokens."""

import json
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.algorithms import RSAAlgorithm

from auth_service.application.ports.security import (
    AccessTokenClaims,
    AccessTokenService,
    IssuedAccessToken,
)
from auth_service.domain.entities import User
from auth_service.domain.exceptions import InvalidAccessTokenError

ACCESS_TOKEN_TYPE = "access"
SIGNING_ALGORITHM = "RS256"


class JwtAccessTokenService(AccessTokenService):
    """Issues RS256-signed JWT access tokens and publishes their JWKS.

    Only this service holds the private key. Client applications verify
    tokens with the public key from ``/.well-known/jwks.json``, so they
    can trust tokens without being able to forge them.
    """

    def __init__(
        self,
        private_key_pem: str,
        key_id: str,
        time_to_live: timedelta,
        issuer: str,
        audience: str,
    ) -> None:
        """Create the service.

        Parameters
        ----------
        private_key_pem : str
            RSA private key in PEM format (PKCS#8 or PKCS#1).
        key_id : str
            Identifier placed in the ``kid`` header and in the JWKS, so
            keys can be rotated without breaking verification.
        time_to_live : timedelta
            Lifetime of each access token.
        issuer : str
            Value of the ``iss`` claim, checked on decoding.
        audience : str
            Value of the ``aud`` claim, checked on decoding.

        Returns
        -------
        None

        Raises
        ------
        ValueError
            When the key is not a valid RSA private key.
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
        )
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError("The JWT signing key must be an RSA private key.")
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._key_id = key_id
        self._time_to_live = time_to_live
        self._issuer = issuer
        self._audience = audience

    def issue(
        self,
        user: User,
        session_id: UUID,
        issued_at: datetime,
    ) -> IssuedAccessToken:
        """Issue a signed access token.

        Parameters
        ----------
        user : User
            User the token is issued to (``sub``, ``email`` and ``name``
            claims).
        session_id : UUID
            Session the token belongs to (``sid`` claim).
        issued_at : datetime
            Moment of issue (``iat`` claim).

        Returns
        -------
        IssuedAccessToken
            The encoded token and its expiration moment.
        """
        expires_at = issued_at + self._time_to_live
        token = jwt.encode(
            {
                "sub": str(user.id),
                "sid": str(session_id),
                "email": user.email,
                "name": user.full_name,
                "typ": ACCESS_TOKEN_TYPE,
                "iss": self._issuer,
                "aud": self._audience,
                "iat": issued_at,
                "exp": expires_at,
            },
            self._private_key,
            algorithm=SIGNING_ALGORITHM,
            headers={"kid": self._key_id},
        )
        return IssuedAccessToken(token=token, expires_at=expires_at)

    def decode(
        self,
        token: str,
    ) -> AccessTokenClaims:
        """Validate a token and extract its claims.

        Parameters
        ----------
        token : str
            Encoded access token.

        Returns
        -------
        AccessTokenClaims
            User and session of the token.

        Raises
        ------
        InvalidAccessTokenError
            When the signature, issuer, audience, type or expiration is
            invalid, or a required claim is missing.
        """
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=[SIGNING_ALGORITHM],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": ["sub", "sid", "exp", "iat", "iss", "aud"]
                },
            )
            if payload.get("typ") != ACCESS_TOKEN_TYPE:
                raise InvalidAccessTokenError()
            return AccessTokenClaims(
                user_id=UUID(payload["sub"]),
                session_id=UUID(payload["sid"]),
            )
        except (jwt.PyJWTError, ValueError) as error:
            raise InvalidAccessTokenError() from error

    def public_key_set(self) -> dict[str, Any]:
        """Return the JWKS with the public half of the signing key.

        Returns
        -------
        dict[str, Any]
            ``{"keys": [<RSA public JWK>]}`` with ``kid``, ``alg`` and
            ``use`` set.
        """
        public_jwk = json.loads(RSAAlgorithm.to_jwk(self._public_key))
        public_jwk.update(
            {"kid": self._key_id, "alg": SIGNING_ALGORITHM, "use": "sig"}
        )
        return {"keys": [public_jwk]}

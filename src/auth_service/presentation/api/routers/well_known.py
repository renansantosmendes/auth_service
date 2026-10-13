"""Discovery endpoint that client applications use to verify tokens."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response

from auth_service.application.ports.security import AccessTokenService
from auth_service.presentation.api.dependencies import (
    get_access_token_service,
)

JWKS_CACHE_SECONDS = 3600

router = APIRouter(tags=["Token verification"])


@router.get(
    "/.well-known/jwks.json",
    summary="Public keys that verify access tokens",
    description=(
        "JSON Web Key Set (RFC 7517) with the public RSA key that signs the "
        "access tokens (RS256).\n\n"
        "Client applications fetch it once, cache it, and verify each "
        "`Authorization: Bearer <access_token>` locally, checking the "
        "signature, `exp`, `iss` (`AUTH_JWT_ISSUER`) and `aud` "
        "(`AUTH_JWT_AUDIENCE`). They never receive the private key, so "
        "they can trust tokens but cannot issue them. Pick the key whose "
        "`kid` matches the token header; when keys are rotated, the new "
        "`kid` appears here.\n\n"
        "A local check does not see sign-outs before the access token "
        "expires (15 minutes by default). When that matters, call "
        "`GET /api/v1/auth/me` with the token instead."
    ),
    response_description="The JSON Web Key Set.",
)
def read_jwks(
    response: Response,
    access_token_service: Annotated[
        AccessTokenService, Depends(get_access_token_service)
    ],
) -> dict[str, Any]:
    """Publish the public keys of the token signer.

    Parameters
    ----------
    response : Response
        Response whose cache headers are set.
    access_token_service : AccessTokenService
        Service that owns the signing key.

    Returns
    -------
    dict[str, Any]
        The JSON Web Key Set.
    """
    response.headers["Cache-Control"] = f"public, max-age={JWKS_CACHE_SECONDS}"
    return access_token_service.public_key_set()

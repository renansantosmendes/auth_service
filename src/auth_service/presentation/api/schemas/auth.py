"""Request and response bodies of the authentication endpoints."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from auth_service.application.dto import SessionTokens
from auth_service.domain.entities import User


class LoginRequest(BaseModel):
    """Credentials informed on the sign-in screen."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "email": "camila.torres@example.com",
                    "password": "<your-password>",
                    "keep_signed_in": True,
                }
            ]
        }
    )

    email: EmailStr = Field(
        description="E-mail of the account (case-insensitive).",
    )
    password: str = Field(
        min_length=1,
        max_length=256,
        description="Password of the account, in plain text.",
    )
    keep_signed_in: bool = Field(
        default=False,
        description=(
            "Matches the *Keep me signed in on this device* checkbox. When "
            "`true`, the refresh token lives for "
            "`KEEP_SIGNED_IN_TTL_DAYS` (default 30 days) instead of "
            "`REFRESH_TOKEN_TTL_HOURS` (default 12 hours)."
        ),
    )
    application: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern="^[a-z0-9][a-z0-9_-]*$",
        description=(
            "Application the user is signing in to, for example `finbrain`. "
            "When given, the account must have active access to it; otherwise "
            "the answer is `403` (`application_access_denied`)."
        ),
    )


class RefreshRequest(BaseModel):
    """Refresh token to exchange for new credentials."""

    refresh_token: str = Field(
        min_length=1,
        max_length=512,
        description=(
            "Refresh token received from `POST /auth/login` or from the "
            "previous `POST /auth/refresh`."
        ),
        examples=["<refresh-token>"],
    )


class TokenResponse(BaseModel):
    """Credentials of a session."""

    access_token: str = Field(
        description=(
            "Short-lived JWT. Send it in the `Authorization: Bearer "
            "<access_token>` header of authenticated requests."
        ),
        examples=["<access-token>"],
    )
    token_type: Literal["bearer"] = Field(
        default="bearer",
        description="Authentication scheme of the access token.",
    )
    expires_in: int = Field(
        description="Seconds until the access token expires.",
        examples=[900],
    )
    access_token_expires_at: datetime = Field(
        description="Expiration moment of the access token (UTC).",
    )
    refresh_token: str = Field(
        description=(
            "Opaque token used once in `POST /auth/refresh` to obtain new "
            "credentials. Store it securely; each refresh returns a new "
            "one and invalidates the previous."
        ),
        examples=["<refresh-token>"],
    )
    refresh_token_expires_at: datetime = Field(
        description="Expiration moment of the refresh token (UTC).",
    )

    @classmethod
    def from_session_tokens(
        cls,
        tokens: SessionTokens,
        issued_at: datetime,
    ) -> "TokenResponse":
        """Build the response from the session credentials.

        Parameters
        ----------
        tokens : SessionTokens
            Credentials returned by a use case.
        issued_at : datetime
            Current moment, used to compute ``expires_in``.

        Returns
        -------
        TokenResponse
            The response body.
        """
        return cls(
            access_token=tokens.access_token,
            expires_in=max(
                0,
                int(
                    (
                        tokens.access_token_expires_at - issued_at
                    ).total_seconds()
                ),
            ),
            access_token_expires_at=tokens.access_token_expires_at,
            refresh_token=tokens.refresh_token,
            refresh_token_expires_at=tokens.refresh_token_expires_at,
        )


class UserResponse(BaseModel):
    """Profile of a user."""

    id: UUID = Field(
        description=(
            "Identifier of the user. It is also the `sub` claim of the "
            "access token, the stable key client applications should use."
        ),
    )
    email: EmailStr = Field(
        description="E-mail of the account.",
        examples=["camila.torres@example.com"],
    )
    full_name: str = Field(
        description="Name displayed by the client applications.",
        examples=["Camila Torres"],
    )
    last_login_at: datetime | None = Field(
        description=(
            "Moment of the last successful sign-in (UTC). In the login "
            "response it already reflects the current sign-in."
        ),
    )

    @classmethod
    def from_user(
        cls,
        user: User,
    ) -> "UserResponse":
        """Build the response from a user.

        Parameters
        ----------
        user : User
            User returned by a use case.

        Returns
        -------
        UserResponse
            The response body.
        """
        return cls(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            last_login_at=user.last_login_at,
        )


class LoginResponse(TokenResponse):
    """Credentials of the new session and the signed-in user."""

    user: UserResponse = Field(description="The signed-in user.")

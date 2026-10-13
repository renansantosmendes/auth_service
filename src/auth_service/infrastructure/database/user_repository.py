"""PostgreSQL implementation of the user repository."""

from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg import Connection, errors

from auth_service.application.ports.repositories import UserRepository
from auth_service.domain.entities import User
from auth_service.domain.exceptions import EmailAlreadyRegisteredError

USER_COLUMNS = """
    id, email, full_name, password_hash, is_active,
    last_login_at
"""


def map_user(row: dict[str, Any]) -> User:
    """Convert a row of ``identity.users`` into a domain entity.

    Parameters
    ----------
    row : dict[str, Any]
        Row with the columns listed in ``USER_COLUMNS``.

    Returns
    -------
    User
        The corresponding user.
    """
    return User(
        id=row["id"],
        email=row["email"],
        full_name=row["full_name"],
        password_hash=row["password_hash"],
        is_active=row["is_active"],
        last_login_at=row["last_login_at"],
    )


class PostgresUserRepository(UserRepository):
    """Reads and updates ``identity.users``."""

    def __init__(
        self,
        connection: Connection,
    ) -> None:
        """Create the repository.

        Parameters
        ----------
        connection : Connection
            Open connection whose transaction is managed by the unit of
            work.

        Returns
        -------
        None
        """
        self._connection = connection

    def get_by_email(
        self,
        email: str,
    ) -> User | None:
        """Find a user by e-mail; the ``citext`` column ignores case.

        Parameters
        ----------
        email : str
            E-mail address.

        Returns
        -------
        User | None
            The user, or ``None`` when no account uses the e-mail.
        """
        row = self._connection.execute(
            f"SELECT {USER_COLUMNS} FROM identity.users WHERE email = %s",
            (email,),
        ).fetchone()
        return map_user(row) if row else None

    def get_by_id(
        self,
        user_id: UUID,
    ) -> User | None:
        """Find a user by identifier.

        Parameters
        ----------
        user_id : UUID
            Identifier of the user.

        Returns
        -------
        User | None
            The user, or ``None`` when it does not exist.
        """
        row = self._connection.execute(
            f"SELECT {USER_COLUMNS} FROM identity.users WHERE id = %s",
            (user_id,),
        ).fetchone()
        return map_user(row) if row else None

    def update_password_hash(
        self,
        user_id: UUID,
        password_hash: str,
    ) -> None:
        """Replace the stored password hash of a user.

        Parameters
        ----------
        user_id : UUID
            Identifier of the user.
        password_hash : str
            New password hash.

        Returns
        -------
        None
        """
        self._connection.execute(
            "UPDATE identity.users SET password_hash = %s WHERE id = %s",
            (password_hash, user_id),
        )

    def update_last_login(
        self,
        user_id: UUID,
        moment: datetime,
    ) -> None:
        """Record the moment of a successful sign-in.

        Parameters
        ----------
        user_id : UUID
            Identifier of the user.
        moment : datetime
            Moment of the sign-in.

        Returns
        -------
        None
        """
        self._connection.execute(
            "UPDATE identity.users SET last_login_at = %s WHERE id = %s",
            (moment, user_id),
        )

    def create(
        self,
        email: str,
        full_name: str,
        password_hash: str | None,
    ) -> User:
        """Insert a new active user.

        Parameters
        ----------
        email : str
            Unique e-mail address; the ``citext`` column ignores case.
        full_name : str
            Name displayed by the client applications.
        password_hash : str | None
            Hash of the initial password, or ``None``.

        Returns
        -------
        User
            The stored user.

        Raises
        ------
        EmailAlreadyRegisteredError
            When another account already uses the e-mail.
        """
        try:
            row = self._connection.execute(
                f"""
                INSERT INTO identity.users (email, full_name, password_hash)
                VALUES (%s, %s, %s)
                RETURNING {USER_COLUMNS}
                """,
                (email, full_name, password_hash),
            ).fetchone()
        except errors.UniqueViolation as error:
            raise EmailAlreadyRegisteredError() from error
        return map_user(row)

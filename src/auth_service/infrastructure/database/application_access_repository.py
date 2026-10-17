"""PostgreSQL implementation of the application access repository."""

from datetime import datetime
from uuid import UUID

from psycopg import Connection

from auth_service.application.ports.repositories import (
    ApplicationAccessRepository,
)


class PostgresApplicationAccessRepository(ApplicationAccessRepository):
    """Reads and updates ``identity.applications`` and
    ``identity.user_applications``."""

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

    def application_is_active(
        self,
        application_code: str,
    ) -> bool:
        """Check the catalog for an active application.

        Parameters
        ----------
        application_code : str
            Stable identifier of the application.

        Returns
        -------
        bool
            ``True`` when the application exists and is active.
        """
        row = self._connection.execute(
            "SELECT 1 AS found FROM identity.applications "
            "WHERE code = %s AND is_active",
            (application_code,),
        ).fetchone()
        return row is not None

    def has_active_access(
        self,
        user_id: UUID,
        application_code: str,
    ) -> bool:
        """Check for a grant that has not been revoked.

        Parameters
        ----------
        user_id : UUID
            Identifier of the user.
        application_code : str
            Stable identifier of the application.

        Returns
        -------
        bool
            ``True`` when the grant exists and is not revoked.
        """
        row = self._connection.execute(
            "SELECT 1 AS found FROM identity.user_applications "
            "WHERE user_id = %s AND application_code = %s "
            "AND revoked_at IS NULL",
            (user_id, application_code),
        ).fetchone()
        return row is not None

    def grant(
        self,
        user_id: UUID,
        application_code: str,
        moment: datetime,
    ) -> None:
        """Insert the grant, or reactivate a revoked one.

        Parameters
        ----------
        user_id : UUID
            Identifier of the user.
        application_code : str
            Stable identifier of the application.
        moment : datetime
            Moment of the grant.

        Returns
        -------
        None
        """
        self._connection.execute(
            "INSERT INTO identity.user_applications "
            "(user_id, application_code, granted_at, revoked_at) "
            "VALUES (%s, %s, %s, NULL) "
            "ON CONFLICT (user_id, application_code) DO UPDATE "
            "SET granted_at = EXCLUDED.granted_at, revoked_at = NULL",
            (user_id, application_code, moment),
        )

    def revoke(
        self,
        user_id: UUID,
        application_code: str,
        moment: datetime,
    ) -> None:
        """Mark the grant as revoked, keeping its row.

        Parameters
        ----------
        user_id : UUID
            Identifier of the user.
        application_code : str
            Stable identifier of the application.
        moment : datetime
            Moment of the revocation.

        Returns
        -------
        None
        """
        self._connection.execute(
            "UPDATE identity.user_applications SET revoked_at = %s "
            "WHERE user_id = %s AND application_code = %s "
            "AND revoked_at IS NULL",
            (moment, user_id, application_code),
        )

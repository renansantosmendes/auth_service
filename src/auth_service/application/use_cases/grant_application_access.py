"""Use case: give or remove a user's access to an application."""

from auth_service.application import audit_actions
from auth_service.application.ports.clock import Clock
from auth_service.application.ports.repositories import AuditEvent
from auth_service.application.ports.unit_of_work import UnitOfWork
from auth_service.domain.entities import User
from auth_service.domain.exceptions import (
    AccountNotFoundError,
    ApplicationNotFoundError,
)


class GrantApplicationAccessUseCase:
    """Grants or revokes an application for the account of an e-mail."""

    def __init__(
        self,
        unit_of_work: UnitOfWork,
        clock: Clock,
    ) -> None:
        """Create the use case.

        Parameters
        ----------
        unit_of_work : UnitOfWork
            Transaction boundary and repositories.
        clock : Clock
            Source of the current time, recorded with the change.

        Returns
        -------
        None
        """
        self._unit_of_work = unit_of_work
        self._clock = clock

    def execute(
        self,
        email: str,
        application_code: str,
        revoke: bool = False,
    ) -> User:
        """Grant or revoke the application and record the change.

        Parameters
        ----------
        email : str
            E-mail of the account, ignoring letter case.
        application_code : str
            Stable identifier of the application, for example ``finbrain``.
        revoke : bool
            ``True`` to remove the access instead of granting it.

        Returns
        -------
        User
            The account whose access changed.

        Raises
        ------
        AccountNotFoundError
            When no account uses the e-mail.
        ApplicationNotFoundError
            When the application is not in the catalog or is inactive.

        Example
        -------
        >>> use_case.execute("ana@example.com", "finbrain")  # doctest: +SKIP
        """
        moment = self._clock.now()
        with self._unit_of_work as uow:
            user = uow.users.get_by_email(email.strip())
            if user is None:
                raise AccountNotFoundError()
            if not uow.application_access.application_is_active(application_code):
                raise ApplicationNotFoundError()
            if revoke:
                uow.application_access.revoke(user.id, application_code, moment)
                action = audit_actions.APPLICATION_ACCESS_REVOKED
            else:
                uow.application_access.grant(user.id, application_code, moment)
                action = audit_actions.APPLICATION_ACCESS_GRANTED
            uow.audit_log.record(
                AuditEvent(
                    action=action,
                    entity_type=audit_actions.USER_ENTITY,
                    entity_id=user.id,
                    details={"application": application_code},
                )
            )
            uow.commit()
        return user

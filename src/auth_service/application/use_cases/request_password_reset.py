"""Use case: send a password recovery link by e-mail."""

import logging
import math

from auth_service.application import audit_actions
from auth_service.application.dto import RequestContext
from auth_service.application.policies import PasswordResetPolicy
from auth_service.application.ports.clock import Clock
from auth_service.application.ports.email import (
    EmailDeliveryError,
    EmailSender,
)
from auth_service.application.ports.repositories import AuditEvent
from auth_service.application.ports.security import (
    OpaqueTokenGenerator,
)
from auth_service.application.ports.unit_of_work import UnitOfWork
from auth_service.application.services.password_reset_email import (
    build_password_reset_email,
)

logger = logging.getLogger(__name__)


class RequestPasswordResetUseCase:
    """Creates a single-use reset token and e-mails its link."""

    def __init__(
        self,
        unit_of_work: UnitOfWork,
        token_generator: OpaqueTokenGenerator,
        email_sender: EmailSender,
        reset_policy: PasswordResetPolicy,
        clock: Clock,
    ) -> None:
        """Create the use case.

        Parameters
        ----------
        unit_of_work : UnitOfWork
            Transaction boundary and repositories.
        token_generator : OpaqueTokenGenerator
            Creates and hashes the reset token.
        email_sender : EmailSender
            Delivers the recovery e-mail.
        reset_policy : PasswordResetPolicy
            Token lifetime and reset page address.
        clock : Clock
            Source of the current time.

        Returns
        -------
        None
        """
        self._unit_of_work = unit_of_work
        self._token_generator = token_generator
        self._email_sender = email_sender
        self._reset_policy = reset_policy
        self._clock = clock

    def execute(
        self,
        email: str,
        context: RequestContext,
    ) -> None:
        """Send recovery instructions when the account exists.

        The call never reveals whether the e-mail is registered: it
        returns normally in every case, and delivery failures are only
        logged.

        Parameters
        ----------
        email : str
            Institutional e-mail informed by the user.
        context : RequestContext
            Information about the client.

        Returns
        -------
        None
        """
        moment = self._clock.now()
        logger.info("Step 1/5: looking up the account for the reset request.")
        with self._unit_of_work as uow:
            user = uow.users.get_by_email(email)
            if user is None:
                logger.info(
                    "Step 1/5 result: no account uses this e-mail. "
                    "Nothing is stored or sent."
                )
                return
            logger.info(
                "Step 1/5 result: account %s found (active: %s, password "
                "set: %s).",
                user.id,
                user.is_active,
                user.password_hash is not None,
            )
            if not user.can_sign_in_with_password:
                logger.info(
                    "Account %s cannot sign in with a password; nothing is "
                    "stored or sent.",
                    user.id,
                )
                return
            token = self._token_generator.generate()
            expires_at = moment + self._reset_policy.token_ttl
            logger.info(
                "Step 2/5: creating a single-use reset token for account %s, "
                "valid until %s.",
                user.id,
                expires_at.isoformat(),
            )
            uow.password_reset_tokens.create(
                user_id=user.id,
                token_hash=self._token_generator.hash(token),
                expires_at=expires_at,
            )
            logger.info("Step 3/5: recording the audit event for account %s.", user.id)
            uow.audit_log.record(
                AuditEvent(
                    action=audit_actions.PASSWORD_RESET_REQUESTED,
                    actor_user_id=user.id,
                    entity_type=audit_actions.USER_ENTITY,
                    entity_id=user.id,
                    ip_address=context.ip_address,
                )
            )
            uow.commit()
            logger.info("Step 3/5 result: token and audit event committed.")
        logger.info("Step 4/5: building the recovery e-mail for account %s.", user.id)
        message = build_password_reset_email(
            recipient=user.email,
            full_name=user.full_name,
            reset_link=self._reset_policy.build_reset_link(token),
            validity_minutes=math.ceil(
                self._reset_policy.token_ttl.total_seconds() / 60
            ),
            application_name=self._reset_policy.application_name,
        )
        logger.info(
            "Step 5/5: handing the recovery e-mail to %s for account %s.",
            type(self._email_sender).__name__,
            user.id,
        )
        try:
            self._email_sender.send(message)
        except EmailDeliveryError:
            logger.exception(
                "Step 5/5 failed: could not deliver the password reset "
                "e-mail of account %s.",
                user.id,
            )
            return
        logger.info(
            "Step 5/5 done: the recovery e-mail was accepted for account %s.",
            user.id,
        )

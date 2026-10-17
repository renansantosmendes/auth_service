"""E-mail sender that delivers messages through the Resend API."""

import logging

import resend

from auth_service.application.ports.email import (
    EmailDeliveryError,
    EmailMessage,
    EmailSender,
)
from auth_service.infrastructure.logging_config import mask_email

logger = logging.getLogger(__name__)


class ResendEmailSender(EmailSender):
    """Sends plain-text messages with the Resend API.

    The sender address must belong to a domain verified in Resend.
    """

    def __init__(
        self,
        api_key: str,
        sender: str,
    ) -> None:
        """Create the sender.

        Parameters
        ----------
        api_key : str
            Resend API key, read from the environment and never logged.
        sender : str
            Address placed in the ``From`` field, on a verified domain.

        Returns
        -------
        None
        """
        self._api_key = api_key
        self._sender = sender

    def send(
        self,
        message: EmailMessage,
    ) -> None:
        """Deliver a plain-text message through Resend.

        Parameters
        ----------
        message : EmailMessage
            Message to deliver.

        Returns
        -------
        None

        Raises
        ------
        EmailDeliveryError
            When the Resend API rejects or cannot receive the message.
        """
        resend.api_key = self._api_key
        logger.info(
            "Calling the Resend API: from %s to %s, subject %r, %d characters.",
            self._sender,
            mask_email(message.recipient),
            message.subject,
            len(message.body),
        )
        try:
            response = resend.Emails.send(
                {
                    "from": self._sender,
                    "to": [message.recipient],
                    "subject": message.subject,
                    "text": message.body,
                }
            )
        except (resend.exceptions.ResendError, OSError) as error:
            logger.error(
                "Resend API call failed for %s: %s",
                mask_email(message.recipient),
                error,
            )
            raise EmailDeliveryError(
                f"Resend could not deliver the message: {error}"
            ) from error
        logger.info(
            "Resend API accepted the message to %s (email id %s).",
            mask_email(message.recipient),
            response.get("id", "unknown"),
        )

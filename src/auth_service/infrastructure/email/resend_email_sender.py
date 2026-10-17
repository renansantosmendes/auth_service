"""E-mail sender that delivers messages through the Resend API."""

import resend

from auth_service.application.ports.email import (
    EmailDeliveryError,
    EmailMessage,
    EmailSender,
)


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
        try:
            resend.Emails.send(
                {
                    "from": self._sender,
                    "to": [message.recipient],
                    "subject": message.subject,
                    "text": message.body,
                }
            )
        except (resend.exceptions.ResendError, OSError) as error:
            raise EmailDeliveryError(
                f"Resend could not deliver the message: {error}"
            ) from error

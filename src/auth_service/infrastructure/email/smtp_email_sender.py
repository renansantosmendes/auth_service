"""E-mail sender that delivers messages through an SMTP server."""

import logging
import smtplib
import ssl
from email.message import EmailMessage as MimeMessage

from auth_service.application.ports.email import (
    EmailDeliveryError,
    EmailMessage,
    EmailSender,
)
from auth_service.infrastructure.logging_config import mask_email

logger = logging.getLogger(__name__)


class SmtpEmailSender(EmailSender):
    """Sends messages with ``smtplib``, using STARTTLS when enabled."""

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
        timeout_seconds: int = 10,
    ) -> None:
        """Create the sender.

        Parameters
        ----------
        host : str
            SMTP server host name.
        port : int
            SMTP server port, usually 587 for STARTTLS.
        sender : str
            Address placed in the ``From`` header.
        username : str | None
            Login of the SMTP account, when authentication is required.
        password : str | None
            Password of the SMTP account.
        use_tls : bool
            Whether to upgrade the connection with STARTTLS.
        timeout_seconds : int
            Maximum time to wait for the server.

        Returns
        -------
        None
        """
        self._host = host
        self._port = port
        self._sender = sender
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._timeout_seconds = timeout_seconds

    def send(
        self,
        message: EmailMessage,
    ) -> None:
        """Deliver a plain-text message.

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
            When the server is unreachable or rejects the login or the
            message.
        """
        mime_message = MimeMessage()
        mime_message["From"] = self._sender
        mime_message["To"] = message.recipient
        mime_message["Subject"] = message.subject
        mime_message.set_content(message.body)
        logger.info(
            "Connecting to SMTP server %s:%s (STARTTLS: %s, login: %s) to "
            "send to %s.",
            self._host,
            self._port,
            self._use_tls,
            bool(self._username and self._password),
            mask_email(message.recipient),
        )
        try:
            with smtplib.SMTP(
                self._host,
                self._port,
                timeout=self._timeout_seconds,
            ) as client:
                if self._use_tls:
                    client.starttls(context=ssl.create_default_context())
                    logger.info("SMTP STARTTLS negotiated.")
                if self._username and self._password:
                    client.login(self._username, self._password)
                    logger.info("SMTP login accepted.")
                client.send_message(mime_message)
        except (smtplib.SMTPException, OSError) as error:
            logger.error(
                "SMTP delivery to %s failed: %s",
                mask_email(message.recipient),
                error,
            )
            raise EmailDeliveryError(str(error)) from error
        logger.info(
            "SMTP server accepted the message to %s.",
            mask_email(message.recipient),
        )

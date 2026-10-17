"""Chooses the e-mail sender configured in the settings."""

from auth_service.application.ports.email import EmailSender
from auth_service.infrastructure.config import Settings
from auth_service.infrastructure.email.logging_email_sender import (
    LoggingEmailSender,
)
from auth_service.infrastructure.email.resend_email_sender import (
    ResendEmailSender,
)
from auth_service.infrastructure.email.smtp_email_sender import (
    SmtpEmailSender,
)


def build_email_sender(settings: Settings) -> EmailSender:
    """Create the e-mail sender selected by ``EMAIL_BACKEND``.

    Parameters
    ----------
    settings : Settings
        Application settings.

    Returns
    -------
    EmailSender
        A Resend sender, an SMTP sender, or a logging sender in development.

    Raises
    ------
    ValueError
        When Resend is selected without an API key or sender address, or
        SMTP is selected without host or sender address.
    """
    if settings.email_backend == "console":
        return LoggingEmailSender()
    if settings.email_backend == "resend":
        if not settings.resend_api_key or not settings.resend_from:
            raise ValueError(
                "RESEND_API_KEY and RESEND_FROM are required when "
                "EMAIL_BACKEND is 'resend'."
            )
        return ResendEmailSender(
            api_key=settings.resend_api_key.get_secret_value(),
            sender=settings.resend_from,
        )
    if not settings.smtp_host or not settings.smtp_sender:
        raise ValueError(
            "SMTP_HOST and SMTP_SENDER are required when EMAIL_BACKEND "
            "is 'smtp'."
        )
    return SmtpEmailSender(
        host=settings.smtp_host,
        port=settings.smtp_port,
        sender=settings.smtp_sender,
        username=settings.smtp_username,
        password=settings.smtp_password.get_secret_value()
        if settings.smtp_password
        else None,
        use_tls=settings.smtp_use_tls,
    )

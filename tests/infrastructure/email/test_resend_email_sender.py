"""Tests of the Resend e-mail sender and of its selection by the factory."""

import pytest
import resend

from auth_service.application.ports.email import EmailDeliveryError, EmailMessage
from auth_service.infrastructure.config import Settings
from auth_service.infrastructure.email.factory import build_email_sender
from auth_service.infrastructure.email.resend_email_sender import ResendEmailSender
from tests.credentials import JWT_PRIVATE_KEY

SENDER = "noreply@synapseaisolutions.com"
MESSAGE = EmailMessage(
    recipient="ana@example.com",
    subject="Redefinir senha",
    body="Use o link para redefinir sua senha.",
)


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Replace the Resend call and record the payloads it receives.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Fixture used to replace the library function.

    Returns
    -------
    list[dict]
        Payloads sent to ``resend.Emails.send``.
    """
    payloads: list[dict] = []
    monkeypatch.setattr(
        resend.Emails,
        "send",
        lambda params: payloads.append(params) or {"id": "re_1"},
    )
    return payloads


def test_send_builds_the_resend_payload_and_sets_the_key(sent: list[dict]) -> None:
    """The message reaches Resend with the sender, recipient and body.

    Parameters
    ----------
    sent : list[dict]
        Payloads recorded by the fake.

    Returns
    -------
    None
    """
    ResendEmailSender(api_key="re_test_key", sender=SENDER).send(MESSAGE)
    assert sent == [
        {
            "from": SENDER,
            "to": ["ana@example.com"],
            "subject": "Redefinir senha",
            "text": "Use o link para redefinir sua senha.",
        }
    ]
    assert resend.api_key == "re_test_key"


def test_resend_errors_become_delivery_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """A rejected message is reported as an e-mail delivery error.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Fixture used to make the library call fail.

    Returns
    -------
    None
    """

    def reject(params: dict) -> dict:
        raise resend.exceptions.ResendError(
            422, "validation_error", "domain not verified", "Verify the sender domain."
        )

    monkeypatch.setattr(resend.Emails, "send", reject)
    with pytest.raises(EmailDeliveryError):
        ResendEmailSender(api_key="re_test_key", sender=SENDER).send(MESSAGE)


def settings(**overrides: object) -> Settings:
    """Build settings for the e-mail factory without reading any file.

    Parameters
    ----------
    **overrides : object
        Values that replace the defaults.

    Returns
    -------
    Settings
        Settings used in the test.
    """
    return Settings(
        _env_file=None,
        AUTH_DATABASE_URL="postgresql://unused/test",
        AUTH_JWT_PRIVATE_KEY=JWT_PRIVATE_KEY,
        **overrides,
    )


def test_factory_selects_resend_when_configured() -> None:
    """EMAIL_BACKEND=resend yields the Resend sender.

    Returns
    -------
    None
    """
    sender = build_email_sender(
        settings(
            email_backend="resend",
            resend_api_key="re_test_key",
            resend_from=SENDER,
        )
    )
    assert isinstance(sender, ResendEmailSender)


def test_factory_refuses_resend_without_key_or_sender() -> None:
    """Resend needs both the API key and the sender address.

    Returns
    -------
    None
    """
    with pytest.raises(ValueError):
        build_email_sender(settings(email_backend="resend", resend_from=SENDER))
    with pytest.raises(ValueError):
        build_email_sender(
            settings(email_backend="resend", resend_api_key="re_test_key")
        )

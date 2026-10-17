"""Tests of the logging helpers."""

from auth_service.infrastructure.logging_config import mask_email


def test_mask_email_keeps_only_first_letter_and_domain() -> None:
    """The local part is reduced to its first letter.

    Returns
    -------
    None
    """
    assert mask_email("ana.lima@example.com") == "a***@example.com"


def test_mask_email_hides_text_without_at_sign() -> None:
    """Text that is not an e-mail address is fully hidden.

    Returns
    -------
    None
    """
    assert mask_email("not-an-email") == "***"

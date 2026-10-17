"""Logging setup and helpers that keep sensitive data out of the log."""

import logging

LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"


def configure_logging(level: int = logging.INFO) -> None:
    """Send the application log to standard error, with timestamps.

    Vercel collects standard error in the runtime logs, so every record
    written by the application appears there.

    Parameters
    ----------
    level : int
        Lowest level shown, such as ``logging.DEBUG`` or ``logging.INFO``.

    Returns
    -------
    None
    """
    logging.basicConfig(level=level, format=LOG_FORMAT, force=True)


def mask_email(email: str) -> str:
    """Hide most of an e-mail address so it can be written to the log.

    Parameters
    ----------
    email : str
        E-mail address to mask.

    Returns
    -------
    str
        First letter of the local part, asterisks and the domain, such as
        ``a***@example.com``. Text without ``@`` becomes ``***``.

    Example
    -------
    >>> mask_email("ana@example.com")
    'a***@example.com'
    """
    local_part, separator, domain = email.partition("@")
    if not separator:
        return "***"
    return f"{local_part[:1]}***@{domain}"

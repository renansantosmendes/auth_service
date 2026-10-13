"""Generate the RSA key that signs the access tokens.

Prints the private key as a single line with ``\\n`` escapes, ready to be
pasted as ``AUTH_JWT_PRIVATE_KEY`` in ``.env`` or in the Vercel project
settings. The key is a secret: never commit it or share it with client
applications, which only need the public JWKS.
"""

import argparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_KEY_SIZE = 3072


def generate_private_key_pem(key_size: int = DEFAULT_KEY_SIZE) -> str:
    """Create a new RSA private key in PKCS#8 PEM format.

    Parameters
    ----------
    key_size : int
        Modulus size in bits.

    Returns
    -------
    str
        The private key in PEM format, with line breaks.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def to_single_line(pem: str) -> str:
    """Escape the line breaks of a PEM so it fits in one variable.

    Parameters
    ----------
    pem : str
        Key in PEM format.

    Returns
    -------
    str
        The key with every line break replaced by ``\\n``.
    """
    return pem.strip().replace("\n", "\\n")


def main(arguments: list[str] | None = None) -> int:
    """Run the command line interface.

    Parameters
    ----------
    arguments : list[str] | None
        Command line arguments; ``sys.argv`` when omitted.

    Returns
    -------
    int
        Process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--bits",
        type=int,
        default=DEFAULT_KEY_SIZE,
        choices=[2048, 3072, 4096],
        help="RSA key size",
    )
    options = parser.parse_args(arguments)
    single_line = to_single_line(generate_private_key_pem(options.bits))
    print(f'AUTH_JWT_PRIVATE_KEY="{single_line}"')
    return 0

"""Create a user account from the command line.

The service has no public sign-up endpoint: administrators create
accounts here. Without ``--password``, the account is created with no
password and the user defines one through "forgot my password".
"""

import argparse
import getpass
from collections.abc import Callable

from dotenv import dotenv_values

from auth_service.application.ports.security import PasswordHasher
from auth_service.application.ports.unit_of_work import UnitOfWork
from auth_service.cli.apply_schema import APPLICATION_URL_KEY, ENV_PATH
from auth_service.domain.entities import User
from auth_service.domain.exceptions import DomainError
from auth_service.domain.password_policy import PasswordPolicy
from auth_service.infrastructure.database.unit_of_work import (
    PostgresUnitOfWork,
)
from auth_service.infrastructure.security.argon2_password_hasher import (
    Argon2PasswordHasher,
)


def create_user(
    unit_of_work: UnitOfWork,
    password_hasher: PasswordHasher,
    email: str,
    full_name: str,
    password: str | None,
) -> User:
    """Validate the data and store a new active user.

    Parameters
    ----------
    unit_of_work : UnitOfWork
        Transaction boundary and repositories.
    password_hasher : PasswordHasher
        Hashes the initial password.
    email : str
        Unique e-mail of the account.
    full_name : str
        Name displayed by the client applications.
    password : str | None
        Initial password, or ``None`` to let the user define it through
        the recovery flow.

    Returns
    -------
    User
        The stored user.

    Raises
    ------
    WeakPasswordError
        When the password breaks the password policy.
    EmailAlreadyRegisteredError
        When another account already uses the e-mail.
    """
    password_hash = None
    if password is not None:
        PasswordPolicy().validate(password, email)
        password_hash = password_hasher.hash(password)
    with unit_of_work as uow:
        user = uow.users.create(
            email=email.strip(),
            full_name=full_name.strip(),
            password_hash=password_hash,
        )
        uow.commit()
    return user


def read_new_password(
    prompt: Callable[[str], str] = getpass.getpass,
) -> str | None:
    """Ask twice for the new password without echoing it.

    Parameters
    ----------
    prompt : Callable[[str], str]
        Function that reads a hidden line from the terminal.

    Returns
    -------
    str | None
        The confirmed password, or ``None`` when both entries differ.
    """
    password = prompt("Password: ")
    if prompt("Confirm password: ") != password:
        return None
    return password


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
    parser.add_argument("email", help="e-mail of the new account")
    parser.add_argument("full_name", help="name shown by the applications")
    parser.add_argument(
        "--password",
        action="store_true",
        help="ask for an initial password (hidden input)",
    )
    options = parser.parse_args(arguments)
    database_url = dotenv_values(ENV_PATH).get(APPLICATION_URL_KEY)
    if not database_url:
        print(f"{APPLICATION_URL_KEY} is missing from .env.")
        return 1
    password = None
    if options.password:
        password = read_new_password()
        if password is None:
            print("The passwords do not match.")
            return 1
    try:
        user = create_user(
            unit_of_work=PostgresUnitOfWork(database_url),
            password_hasher=Argon2PasswordHasher(),
            email=options.email,
            full_name=options.full_name,
            password=password,
        )
    except DomainError as error:
        print(f"{error.message} {' '.join(getattr(error, 'violations', []))}")
        return 1
    print(f"User {user.email} created with id {user.id}.")
    return 0

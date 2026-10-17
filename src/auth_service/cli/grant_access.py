"""Give or remove a user's access to an application from the command line.

The account must already exist (see create-user) and the application must
be active in the identity.applications catalog. Without --revoke, the
access is granted; with --revoke, it is removed and the history is kept.
"""

import argparse

from dotenv import dotenv_values

from auth_service.application.use_cases.grant_application_access import (
    GrantApplicationAccessUseCase,
)
from auth_service.cli.apply_schema import APPLICATION_URL_KEY, ENV_PATH
from auth_service.domain.exceptions import DomainError
from auth_service.infrastructure.clock import SystemClock
from auth_service.infrastructure.database.unit_of_work import (
    PostgresUnitOfWork,
)


def main(arguments: list[str] | None = None) -> int:
    """Run the command line interface.

    Parameters
    ----------
    arguments : list[str] | None
        Command line arguments; ``sys.argv`` when omitted.

    Returns
    -------
    int
        Process exit code: 0 on success, 1 when the change was refused.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("email", help="e-mail of the account")
    parser.add_argument("application", help="application code, e.g. finbrain")
    parser.add_argument(
        "--revoke",
        action="store_true",
        help="remove the access instead of granting it",
    )
    options = parser.parse_args(arguments)
    database_url = dotenv_values(ENV_PATH).get(APPLICATION_URL_KEY)
    if not database_url:
        print(f"{APPLICATION_URL_KEY} is missing from .env.")
        return 1
    use_case = GrantApplicationAccessUseCase(
        unit_of_work=PostgresUnitOfWork(database_url),
        clock=SystemClock(),
    )
    try:
        user = use_case.execute(
            email=options.email,
            application_code=options.application,
            revoke=options.revoke,
        )
    except DomainError as error:
        print(error.message)
        return 1
    action = "removed from" if options.revoke else "granted to"
    print(f"Access to {options.application} {action} {user.email}.")
    return 0

"""Administrative commands of the authentication service.

Usage::

    uv run --no-project python manage.py generate-signing-key
    uv run --no-project python manage.py apply-schema [--rotate]
    uv run --no-project python manage.py create-user EMAIL "FULL NAME" [--password]
"""

import importlib
import sys
from pathlib import Path

SOURCE_DIRECTORY = Path(__file__).resolve().parent / "src"
COMMAND_MODULES = {
    "generate-signing-key": "auth_service.cli.generate_signing_key",
    "apply-schema": "auth_service.cli.apply_schema",
    "create-user": "auth_service.cli.create_user",
}


def run(arguments: list[str]) -> int:
    """Dispatch to the module of the requested command.

    Parameters
    ----------
    arguments : list[str]
        Command name followed by its own arguments.

    Returns
    -------
    int
        Process exit code.
    """
    if not arguments or arguments[0] not in COMMAND_MODULES:
        print(__doc__)
        return 1
    if str(SOURCE_DIRECTORY) not in sys.path:
        sys.path.insert(0, str(SOURCE_DIRECTORY))
    module = importlib.import_module(COMMAND_MODULES[arguments[0]])
    return module.main(arguments[1:])


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))

"""Create the ``identity`` schema in Neon and its restricted application role.

Connects with ``NEON_DATABASE_URL`` (database owner), applies
``db/schema.sql``, creates or updates the ``identity_app`` role and writes
its connection string to ``AUTH_DATABASE_URL`` in ``.env``. The role can
only read and write the rows of the ``identity`` schema: it cannot change
tables, cannot see other schemas, and can only append to the audit log.
"""

import argparse
import secrets
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import psycopg
from dotenv import dotenv_values
from psycopg import sql

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_PATH = PROJECT_ROOT / ".env"
SCHEMA_PATH = PROJECT_ROOT / "db" / "schema.sql"
SCHEMA_NAME = "identity"
APPLICATION_ROLE = "identity_app"
APPLICATION_URL_KEY = "AUTH_DATABASE_URL"

GRANTS_SQL = f"""
REVOKE ALL ON SCHEMA {SCHEMA_NAME} FROM PUBLIC;
GRANT USAGE ON SCHEMA {SCHEMA_NAME} TO {APPLICATION_ROLE};
GRANT SELECT, INSERT, UPDATE, DELETE
  ON {SCHEMA_NAME}.users,
     {SCHEMA_NAME}.user_sessions,
     {SCHEMA_NAME}.password_reset_tokens
  TO {APPLICATION_ROLE};
GRANT SELECT, INSERT ON {SCHEMA_NAME}.audit_log TO {APPLICATION_ROLE};
GRANT SELECT ON {SCHEMA_NAME}.applications TO {APPLICATION_ROLE};
GRANT SELECT, INSERT, UPDATE ON {SCHEMA_NAME}.user_applications
  TO {APPLICATION_ROLE};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {SCHEMA_NAME}
  TO {APPLICATION_ROLE};
ALTER ROLE {APPLICATION_ROLE} SET search_path = {SCHEMA_NAME}, public;
"""


def build_application_url(
    owner_url: str,
    password: str,
) -> str:
    """Derive the application role's connection string from the owner's.

    Parameters
    ----------
    owner_url : str
        Connection string of the database owner.
    password : str
        Password of the application role.

    Returns
    -------
    str
        Same host, database and options, with the application role's
        credentials.

    Example
    -------
    >>> build_application_url("postgresql://owner:x@host/db", "p@ss")
    'postgresql://identity_app:p%40ss@host/db'
    """
    parts = urlsplit(owner_url)
    host = parts.netloc.rsplit("@", 1)[-1]
    credentials = f"{APPLICATION_ROLE}:{quote(password, safe='')}"
    return urlunsplit(parts._replace(netloc=f"{credentials}@{host}"))


def write_env_variable(
    env_path: Path,
    key: str,
    value: str,
) -> None:
    """Set a variable in a ``.env`` file, replacing it when present.

    Parameters
    ----------
    env_path : Path
        Path of the ``.env`` file; it is created when missing.
    key : str
        Variable name.
    value : str
        Variable value, written between double quotes.

    Returns
    -------
    None
    """
    lines = (
        env_path.read_text(encoding="utf-8").splitlines()
        if env_path.exists()
        else []
    )
    entry = f'{key}="{value}"'
    for index, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[index] = entry
            break
    else:
        lines.append(entry)
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def apply_schema(
    owner_url: str,
    rotate_password: bool,
) -> str | None:
    """Apply the schema and grants, creating or updating the role.

    Parameters
    ----------
    owner_url : str
        Connection string of the database owner.
    rotate_password : bool
        Whether to set a new password even if the role already exists.

    Returns
    -------
    str | None
        The new application connection string, or ``None`` when the
        existing role password was kept.
    """
    with psycopg.connect(owner_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM pg_roles WHERE rolname = %s",
                (APPLICATION_ROLE,),
            )
            role_exists = cursor.fetchone() is not None
            password = None
            if not role_exists or rotate_password:
                password = secrets.token_urlsafe(32)
                verb = "ALTER" if role_exists else "CREATE"
                cursor.execute(
                    sql.SQL("{} ROLE {} WITH LOGIN PASSWORD {}").format(
                        sql.SQL(verb),
                        sql.Identifier(APPLICATION_ROLE),
                        sql.Literal(password),
                    )
                )
            cursor.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
            cursor.execute(GRANTS_SQL)
    return build_application_url(owner_url, password) if password else None


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
        "--rotate",
        action="store_true",
        help="generate a new password for the application role",
    )
    options = parser.parse_args(arguments)
    owner_url = dotenv_values(ENV_PATH).get("NEON_DATABASE_URL")
    if not owner_url:
        print("NEON_DATABASE_URL is missing from .env.")
        return 1
    if not dotenv_values(ENV_PATH).get(APPLICATION_URL_KEY):
        options.rotate = True
    application_url = apply_schema(owner_url, options.rotate)
    if application_url:
        write_env_variable(ENV_PATH, APPLICATION_URL_KEY, application_url)
        print(f"Role {APPLICATION_ROLE} ready; {APPLICATION_URL_KEY} saved.")
    else:
        print(f"Role {APPLICATION_ROLE} kept its password.")
    print(f"Schema {SCHEMA_NAME} applied.")
    return 0

# CLAUDE.md

## About this project

Generic authentication service of SynapseAI: sign-in, sessions and
password management shared by every application (CourseGen Studio is the
first client). FastAPI application (package `src/auth_service`) deployed
on Vercel through `api/index.py` and `vercel.json`.

Client applications never read this service's tables: they verify the
RS256 access tokens with the public keys from `/.well-known/jwks.json`
and keep their own profile data keyed by the token's `sub` claim. Keep
the service generic: no application-specific concepts (organizations,
roles, courses) belong here.

## About the architecture

- Clean Architecture with SOLID; dependencies point inwards only:
  `domain` (entities, errors, rules; no I/O) <- `application` (use
  cases, ports, policies, DTOs) <- `infrastructure` (PostgreSQL,
  Argon2, JWT, Resend, SMTP, settings) and `presentation/api` (FastAPI).
- Use cases depend on ports from `application/ports`, never on
  adapters. Wire implementations only in
  `presentation/api/dependencies.py`.
- Business errors are `DomainError` subclasses with a stable `code`;
  map them to HTTP statuses in `presentation/api/error_handlers.py`.
- Document every route for Swagger in English: `summary`,
  `description`, `response_description`, every error status in
  `responses`, and `Field(description=..., examples=...)` in schemas.
- The token contract (claims `sub`, `email`, `name`, `sid`, `iss`,
  `aud`, `iat`, `exp`, `typ`; RS256 with `kid`) is consumed by other
  repositories. Changing it is a breaking change for every client.

## About dependencies and commands

- `requirements.txt` holds only runtime packages (Vercel installs it);
  development tools go in `requirements-dev.txt`.
- Set up: `uv venv` and `uv pip install -r requirements-dev.txt`.
- Run locally: `uv run --no-project uvicorn api.index:app --reload`.
- Administration: `uv run --no-project python manage.py
  generate-signing-key | apply-schema | create-user`.
- Tests: `uv run --no-project pytest -q`.
- Lint: `uv run --no-project pylint --rcfile=.pylintrc src api manage.py`
  and `uv run --no-project pylint --rcfile=tests/.pylintrc tests`. Both
  must score 10/10, as enforced by `.github/workflows/ci.yml`.
- Tests use the in-memory fakes in `tests/fakes.py` and the throwaway
  credentials in `tests/credentials.py`; do not require a database or
  hardcode passwords and keys in tests.

## About the database

- Everything lives in the `identity` schema of the shared Neon database
  (`db/schema.sql`, idempotent). Never read or write other schemas.
- Apply schema changes with `python manage.py apply-schema`, which uses
  `NEON_DATABASE_URL` (owner) only for that. At runtime, connect only with
  `AUTH_DATABASE_URL` (role `identity_app`): it can read and write the
  rows of `identity`, only append to `audit_log`, and cannot change
  tables. When adding tables, update the grants in
  `src/auth_service/cli/apply_schema.py`.

## About secrets

- Secrets are read from a local `.env` file, which is git-ignored.
  Never hardcode keys, passwords or connection strings in code, tests
  or logs. `AUTH_JWT_PRIVATE_KEY` never leaves this service; client
  applications only get the public JWKS.

## About Python code

Always follow these guidelines when writing or editing Python code in
this project:

- Always use `uv` as the package manager whenever a package needs to be
  installed.
- Write all docstrings in English.
- Docstrings must be complete: describe the input parameters
  (`Parameters`) and the return value (`Returns`).
- When a function or method is complex, include a usage example in the
  docstring (`Example` section).
- Respect the per-line character limit in docstrings according to
  PEP 8 / PEP 257 (79 characters).
- Variables, functions, classes and methods must have descriptive,
  meaningful names written in English.
- Use type hints on function and method parameters and return values.
- Do not use type hints on simple variable assignments inside the body
  of the code.
- Do not add comments in the code — keep only the docstrings.
- Whenever a function or method has 2 or more parameters, break the
  signature across multiple lines, one parameter per line, for example:

```python
def func1(
    param_1: type_1,
    param_2: type_2,
    ...
    param_n: type_n,
) -> type_of_return:
```

- Whenever production code is created or changed, add (or update) the
  corresponding unit tests under `tests/`, mirroring the structure of
  `src/`.
- Always check whether the existing documentation (README, docstrings,
  files under `docs/`, if any) is still consistent with the change; if
  it needs an update, update it right away.

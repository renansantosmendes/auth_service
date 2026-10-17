-- =====================================================================
-- Auth Service: database schema (Neon / PostgreSQL 16+)
--
-- Everything lives in the "identity" schema, isolated from the other
-- projects sharing the database. Client applications never read these
-- tables: they trust the access tokens this service signs and keep their
-- own profile tables keyed by the token's "sub" claim (identity.users.id).
--
-- The script is idempotent: it can be run more than once.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE SCHEMA IF NOT EXISTS identity;

CREATE OR REPLACE FUNCTION identity.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- Accounts that can sign in.
CREATE TABLE IF NOT EXISTS identity.users (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email          citext NOT NULL UNIQUE,
  password_hash  text,                        -- Argon2id; NULL until the user defines a password
  full_name      text NOT NULL,
  is_active      boolean NOT NULL DEFAULT true,
  last_login_at  timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS users_touch ON identity.users;
CREATE TRIGGER users_touch BEFORE UPDATE ON identity.users
  FOR EACH ROW EXECUTE FUNCTION identity.touch_updated_at();

-- Signed-in sessions; only the SHA-256 of the refresh token is stored.
CREATE TABLE IF NOT EXISTS identity.user_sessions (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  refresh_token_hash text NOT NULL UNIQUE,
  keep_signed_in     boolean NOT NULL DEFAULT false,
  user_agent         text,
  ip_address         inet,
  created_at         timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  revoked_at         timestamptz
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON identity.user_sessions (user_id);

-- Single-use password recovery tokens; only their SHA-256 is stored.
CREATE TABLE IF NOT EXISTS identity.password_reset_tokens (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  token_hash  text NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);
CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx ON identity.password_reset_tokens (user_id);

-- Append-only trail of sign-ins, sign-outs and password events. Failed
-- sign-ins recorded here also drive the per-account lockout.
CREATE TABLE IF NOT EXISTS identity.audit_log (
  id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_user_id   uuid REFERENCES identity.users(id) ON DELETE SET NULL,
  action          text NOT NULL,              -- "auth.login", "auth.login_failed", ...
  entity_type     text,
  entity_id       uuid,
  details         jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_address      inet,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_log_entity_idx ON identity.audit_log (entity_type, entity_id, action, created_at DESC);

-- Applications that can use the accounts (catalog, maintained by the owner).
CREATE TABLE IF NOT EXISTS identity.applications (
  code       text PRIMARY KEY,               -- stable identifier, e.g. "finbrain"
  name       text NOT NULL,
  is_active  boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO identity.applications (code, name)
VALUES ('finbrain', 'FinBrain')
ON CONFLICT (code) DO NOTHING;

-- Which user may sign in to which application. Revoked grants keep their row
-- so the history stays visible; access requires revoked_at IS NULL.
CREATE TABLE IF NOT EXISTS identity.user_applications (
  user_id           uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  application_code  text NOT NULL REFERENCES identity.applications(code) ON DELETE CASCADE,
  granted_at        timestamptz NOT NULL DEFAULT now(),
  revoked_at        timestamptz,
  PRIMARY KEY (user_id, application_code)
);
CREATE INDEX IF NOT EXISTS user_applications_app_idx ON identity.user_applications (application_code);

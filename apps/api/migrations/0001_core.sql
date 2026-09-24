-- 0001: core identity schema. Applied by apps/api/src/platform/migrate.ts as the owner role.

-- Tenant context. Every tenant-owned table is filtered by this through RLS.
CREATE FUNCTION nexus_current_org() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT nullif(current_setting('app.org_id', true), '')::uuid
$$;

CREATE TABLE organizations (
  id          uuid PRIMARY KEY,
  name        text NOT NULL,
  slug        text NOT NULL UNIQUE,
  settings    jsonb NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id             uuid PRIMARY KEY,
  org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email          text NOT NULL,
  given_name     text NOT NULL DEFAULT '',
  family_name    text NOT NULL DEFAULT '',
  title          text NOT NULL DEFAULT '',
  department     text NOT NULL DEFAULT '',
  status         text NOT NULL DEFAULT 'active'
                 CHECK (status IN ('staged', 'active', 'suspended', 'deprovisioned')),
  password_hash  text,
  attributes     jsonb NOT NULL DEFAULT '{}',
  last_login_at  timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
-- Emails are globally unique among non-deprovisioned users: login is email-first.
CREATE UNIQUE INDEX users_email_live ON users (lower(email)) WHERE status <> 'deprovisioned';
CREATE INDEX users_org ON users (org_id, id DESC);

CREATE TABLE user_roles (
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role)
);

CREATE TABLE groups (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name         text NOT NULL,
  description  text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE group_members (
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  group_id    uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id)
);

CREATE TABLE sessions (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash    bytea NOT NULL UNIQUE,
  state         text NOT NULL CHECK (state IN ('pending_mfa', 'active')),
  client        text NOT NULL DEFAULT 'web',
  ip            text NOT NULL DEFAULT '',
  user_agent    text NOT NULL DEFAULT '',
  mfa_at        timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz
);
CREATE INDEX sessions_user ON sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE auth_factors (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type          text NOT NULL CHECK (type IN ('totp', 'push', 'webauthn')),
  name          text NOT NULL DEFAULT '',
  secret_sealed bytea,   -- TOTP secret, sealed with the platform key
  public_key    bytea,   -- push / webauthn public key
  verified_at   timestamptz,
  last_used_at  timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX auth_factors_user ON auth_factors (user_id);

CREATE TABLE mfa_challenges (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id   uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  number       int  NOT NULL,
  choices      int[] NOT NULL,
  status       text NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  context      jsonb NOT NULL DEFAULT '{}',
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  decided_at   timestamptz
);

-- Audit is append-only for the app role (see grants below).
CREATE TABLE audit_events (
  id              uuid PRIMARY KEY,
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  ts              timestamptz NOT NULL DEFAULT now(),
  type            text NOT NULL,
  outcome         text NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure', 'denied')),
  actor_type      text NOT NULL,
  actor_id        uuid,
  actor_display   text NOT NULL DEFAULT '',
  target_type     text NOT NULL DEFAULT '',
  target_id       uuid,
  target_display  text NOT NULL DEFAULT '',
  session_id      uuid,
  ip              text NOT NULL DEFAULT '',
  user_agent      text NOT NULL DEFAULT '',
  details         jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_events_org_ts ON audit_events (org_id, id DESC);
CREATE INDEX audit_events_target ON audit_events (org_id, target_id, id DESC);
CREATE INDEX audit_events_actor ON audit_events (org_id, actor_id, id DESC);

CREATE TABLE notifications (
  id                 uuid PRIMARY KEY,
  org_id             uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  recipient_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category           text NOT NULL,
  severity           text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  title              text NOT NULL,
  body               text NOT NULL DEFAULT '',
  entity_type        text NOT NULL DEFAULT '',
  entity_id          uuid,
  link               text NOT NULL DEFAULT '',
  actions            jsonb NOT NULL DEFAULT '[]',
  created_at         timestamptz NOT NULL DEFAULT now(),
  read_at            timestamptz,
  archived_at        timestamptz,
  acted_at           timestamptz
);
CREATE INDEX notifications_inbox ON notifications (recipient_user_id, id DESC) WHERE archived_at IS NULL;

-- Row-level security on every tenant-owned table.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','user_roles','groups','group_members','sessions',
                           'auth_factors','mfa_challenges','audit_events','notifications']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations
  USING (id = nexus_current_org()) WITH CHECK (id = nexus_current_org());

-- Real-time fan-out: inbox changes are announced on one channel; the API routes them to SSE clients.
CREATE FUNCTION nexus_notify_inbox() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('nexus_inbox', json_build_object(
    'org_id', NEW.org_id, 'user_id', NEW.recipient_user_id,
    'id', NEW.id, 'op', lower(TG_OP))::text);
  RETURN NEW;
END $$;
CREATE TRIGGER notifications_notify AFTER INSERT OR UPDATE ON notifications
  FOR EACH ROW EXECUTE FUNCTION nexus_notify_inbox();

CREATE FUNCTION nexus_notify_challenge() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('nexus_challenge', json_build_object(
    'org_id', NEW.org_id, 'user_id', NEW.user_id, 'session_id', NEW.session_id,
    'id', NEW.id, 'status', NEW.status)::text);
  RETURN NEW;
END $$;
CREATE TRIGGER mfa_challenges_notify AFTER INSERT OR UPDATE ON mfa_challenges
  FOR EACH ROW EXECUTE FUNCTION nexus_notify_challenge();

-- Narrow, audited cross-tenant lookups. These are the ONLY paths that ignore RLS.
CREATE FUNCTION nexus_auth_find_user(p_email text)
RETURNS TABLE (user_id uuid, org_id uuid, password_hash text, status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id, password_hash, status FROM users
  WHERE lower(email) = lower(p_email) AND status <> 'deprovisioned'
$$;

CREATE FUNCTION nexus_auth_session(p_token_hash bytea)
RETURNS TABLE (session_id uuid, org_id uuid, user_id uuid, state text, client text,
               mfa_at timestamptz, expires_at timestamptz, user_status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT s.id, s.org_id, s.user_id, s.state, s.client, s.mfa_at, s.expires_at, u.status
  FROM sessions s JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL AND s.expires_at > now()
$$;

CREATE FUNCTION nexus_org_slug_taken(p_slug text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM organizations WHERE slug = lower(p_slug))
$$;

CREATE FUNCTION nexus_email_taken(p_email text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = lower(p_email) AND status <> 'deprovisioned')
$$;

-- Grants for the runtime role.
GRANT USAGE ON SCHEMA public TO nexus_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  organizations, users, user_roles, groups, group_members, sessions,
  auth_factors, mfa_challenges, notifications TO nexus_app;
GRANT SELECT, INSERT ON audit_events TO nexus_app;
REVOKE ALL ON FUNCTION nexus_auth_find_user(text), nexus_auth_session(bytea),
  nexus_org_slug_taken(text), nexus_email_taken(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_auth_find_user(text), nexus_auth_session(bytea),
  nexus_org_slug_taken(text), nexus_email_taken(text), nexus_current_org() TO nexus_app;

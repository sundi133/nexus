-- 0004: applications (SSO), assignments, per-tenant signing keys, OIDC authorization codes.

CREATE TABLE applications (
  id                  uuid PRIMARY KEY,
  org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                text NOT NULL,
  protocol            text NOT NULL CHECK (protocol IN ('oidc', 'saml')),
  catalog_key         text,                    -- template it was created from, if any
  status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  launch_url          text NOT NULL DEFAULT '',-- where the app launcher sends people (IdP- or SP-initiated start)
  -- OIDC
  client_id           text UNIQUE,             -- globally unique so the token endpoint can find the app
  client_secret_hash  bytea,                   -- null for public clients (PKCE only)
  redirect_uris       text[] NOT NULL DEFAULT '{}',
  -- Protocol-specific settings (SAML entity ID / ACS, attribute mapping…)
  config              jsonb NOT NULL DEFAULT '{}',
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE app_assignments (
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  app_id          uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  principal_type  text NOT NULL CHECK (principal_type IN ('user', 'group')),
  principal_id    uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, principal_type, principal_id)
);
CREATE INDEX app_assignments_principal ON app_assignments (principal_type, principal_id);

-- Per-tenant token signing keys (RS256: the algorithm every relying party supports).
CREATE TABLE signing_keys (
  id                  uuid PRIMARY KEY,
  org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kid                 text NOT NULL UNIQUE,
  alg                 text NOT NULL DEFAULT 'RS256',
  public_jwk          jsonb NOT NULL,
  private_key_sealed  bytea NOT NULL,
  status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX signing_keys_org ON signing_keys (org_id, status);

-- Authorization codes: single use, 60 seconds, bound to client + redirect URI + PKCE.
CREATE TABLE oidc_codes (
  id              uuid PRIMARY KEY,
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code_hash       bytea NOT NULL UNIQUE,
  app_id          uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id      uuid REFERENCES sessions(id) ON DELETE CASCADE,
  redirect_uri    text NOT NULL,
  scope           text NOT NULL,
  nonce           text,
  code_challenge  text,
  auth_time       timestamptz NOT NULL,
  amr             text[] NOT NULL DEFAULT '{}',
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  used_at         timestamptz
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['applications','app_assignments','signing_keys','oidc_codes']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;

-- Protocol endpoints are addressed by org slug (the tenant's issuer), before any session exists.
CREATE FUNCTION nexus_org_by_slug(p_slug text)
RETURNS TABLE (org_id uuid, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, name FROM organizations WHERE slug = lower(p_slug)
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON applications, app_assignments, signing_keys, oidc_codes TO nexus_app;
REVOKE ALL ON FUNCTION nexus_org_by_slug(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_org_by_slug(text) TO nexus_app;

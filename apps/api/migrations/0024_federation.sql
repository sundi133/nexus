-- 0024: sign in through the organization's existing identity provider (SPEC AUTH-10).
-- Nexus acts as an OIDC relying party / SAML service provider towards Okta, Entra ID, Google, etc.

CREATE TABLE identity_providers (
  id                uuid PRIMARY KEY,
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name              text NOT NULL,
  protocol          text NOT NULL CHECK (protocol IN ('oidc', 'saml')),
  -- OIDC
  issuer            text,
  client_id         text,
  client_secret     bytea,                                  -- sealed
  scopes            text NOT NULL DEFAULT 'openid email profile',
  -- SAML
  idp_entity_id     text,
  idp_sso_url       text,
  idp_certs         text[] NOT NULL DEFAULT '{}',          -- PEM; several during the IdP's certificate rollover
  email_attribute   text NOT NULL DEFAULT '',              -- SAML attribute for email ('' = NameID)
  -- Behaviour
  domains           text[] NOT NULL DEFAULT '{}',          -- verified email domains this IdP signs in (and may vouch for)
  jit_provisioning  boolean NOT NULL DEFAULT true,         -- create people on their first sign-in
  mfa               text NOT NULL DEFAULT 'when_signalled' CHECK (mfa IN ('when_signalled', 'always', 'never')),
  required          boolean NOT NULL DEFAULT false,        -- no passwords or passkeys for these domains
  enabled           boolean NOT NULL DEFAULT true,
  last_test_ok_at   timestamptz,                           -- a successful test sign-in; needed before `required`
  last_login_at     timestamptz,
  created_by        uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name),
  CHECK (protocol <> 'oidc' OR (issuer IS NOT NULL AND client_id IS NOT NULL AND client_secret IS NOT NULL)),
  CHECK (protocol <> 'saml' OR (idp_entity_id IS NOT NULL AND idp_sso_url IS NOT NULL AND cardinality(idp_certs) > 0))
);

-- Who someone is at their IdP (the `sub` claim / persistent NameID), linked to their Nexus account.
CREATE TABLE federated_identities (
  id             uuid PRIMARY KEY,
  org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  idp_id         uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
  subject        text NOT NULL,
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_login_at  timestamptz,
  UNIQUE (idp_id, subject),
  UNIQUE (idp_id, user_id)
);

-- One sign-in attempt: the state/RelayState, single-use, short-lived.
CREATE TABLE federation_requests (
  id               uuid PRIMARY KEY,                      -- sent as OIDC state / SAML RelayState
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  idp_id           uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
  purpose          text NOT NULL CHECK (purpose IN ('login', 'test')),
  nonce            text NOT NULL DEFAULT '',
  code_verifier    text NOT NULL DEFAULT '',
  saml_request_id  text NOT NULL DEFAULT '',
  return_to        text NOT NULL DEFAULT '/',
  client           text NOT NULL DEFAULT 'web',
  requested_by     uuid REFERENCES users(id) ON DELETE CASCADE, -- the admin running a test
  result           jsonb,                                  -- a test's outcome, for the admin to read
  created_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  used_at          timestamptz
);
CREATE INDEX federation_requests_expiry ON federation_requests (expires_at);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['identity_providers','federated_identities','federation_requests']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_providers, federated_identities, federation_requests TO nexus_app;

-- A session's second factor can be "the IdP did MFA".
ALTER TABLE sessions DROP CONSTRAINT sessions_mfa_method_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_mfa_method_check CHECK (mfa_method IN ('totp', 'push', 'webauthn', 'recovery_code', 'idp'));

-- Home-realm discovery, before a tenant is known: which enabled IdP signs in this email domain.
-- Only for domains the organization has proven it owns.
CREATE FUNCTION nexus_federation_for_domain(p_domain text)
RETURNS TABLE (org_id uuid, idp_id uuid, name text, required boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT i.org_id, i.id, i.name, i.required FROM identity_providers i
  JOIN org_domains d ON d.org_id = i.org_id AND d.domain = lower(p_domain) AND d.status IN ('verified', 'failing')
  WHERE i.enabled AND lower(p_domain) = ANY (i.domains)
  ORDER BY i.required DESC, i.created_at
  LIMIT 1
$$;

-- The tenant of a sign-in attempt, from its (unguessable) state.
CREATE FUNCTION nexus_federation_request_org(p_id uuid)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM federation_requests WHERE id = p_id AND used_at IS NULL AND expires_at > now()
$$;

REVOKE ALL ON FUNCTION nexus_federation_for_domain(text), nexus_federation_request_org(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_federation_for_domain(text), nexus_federation_request_org(uuid) TO nexus_app;

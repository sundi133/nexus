-- 0002: TOTP replay protection, MFA enrollment state, invitations, passkeys.

-- TOTP: remember the last accepted 30s time-step so a code can't be replayed (AUTH-02).
ALTER TABLE auth_factors ADD COLUMN last_totp_step bigint;

-- Passkeys (WebAuthn) store the credential alongside the factor (AUTH-03).
ALTER TABLE auth_factors ADD COLUMN credential_id text;
ALTER TABLE auth_factors ADD COLUMN sign_count bigint NOT NULL DEFAULT 0;
ALTER TABLE auth_factors ADD COLUMN transports text[] NOT NULL DEFAULT '{}';
CREATE UNIQUE INDEX auth_factors_credential ON auth_factors (credential_id) WHERE credential_id IS NOT NULL;

-- A session that must enroll MFA before it can do anything else (org MFA policy).
ALTER TABLE sessions DROP CONSTRAINT sessions_state_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_state_check CHECK (state IN ('pending_mfa', 'enroll_mfa', 'active'));

-- Short-lived challenges for WebAuthn ceremonies.
CREATE TABLE auth_challenges (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     text NOT NULL CHECK (purpose IN ('webauthn_register', 'webauthn_authenticate')),
  challenge   text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL
);

-- Invitations: a user is `staged` until they accept and set a password.
CREATE TABLE invitations (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   bytea NOT NULL UNIQUE,
  invited_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  accepted_at  timestamptz,
  revoked_at   timestamptz
);
CREATE INDEX invitations_user ON invitations (user_id);

ALTER TABLE auth_challenges ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth_challenges USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invitations USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());

-- The invitation link is the only thing a new user has, so resolving it must work before a tenant is known.
CREATE FUNCTION nexus_invitation_lookup(p_token_hash bytea)
RETURNS TABLE (invitation_id uuid, org_id uuid, user_id uuid, email text, org_name text, expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT i.id, i.org_id, i.user_id, u.email, o.name, i.expires_at
  FROM invitations i
  JOIN users u ON u.id = i.user_id
  JOIN organizations o ON o.id = i.org_id
  WHERE i.token_hash = p_token_hash AND i.accepted_at IS NULL AND i.revoked_at IS NULL
    AND i.expires_at > now() AND u.status = 'staged'
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON auth_challenges, invitations TO nexus_app;
REVOKE ALL ON FUNCTION nexus_invitation_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_invitation_lookup(bytea) TO nexus_app;

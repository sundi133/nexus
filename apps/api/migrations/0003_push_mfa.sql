-- 0003: push MFA through Nexus Mobile (AUTH-04, MOB-01/02).

-- One-time codes the web console shows as a QR code to pair a phone as an authenticator.
CREATE TABLE device_pairings (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id  uuid REFERENCES sessions(id) ON DELETE CASCADE, -- the web session that asked; activated if it was enrolling
  code_hash   bytea NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);

-- Where to deliver pushes for a paired phone (APNs/FCM token). Content-free: payloads carry IDs only.
CREATE TABLE push_registrations (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  factor_id   uuid REFERENCES auth_factors(id) ON DELETE CASCADE,
  platform    text NOT NULL CHECK (platform IN ('ios', 'android', 'web')),
  token       text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (platform, token)
);

-- Challenges now record which factor answered and why a denial happened.
ALTER TABLE mfa_challenges ADD COLUMN factor_id uuid REFERENCES auth_factors(id) ON DELETE SET NULL;
ALTER TABLE mfa_challenges ADD COLUMN decision_reason text;
CREATE INDEX mfa_challenges_user_pending ON mfa_challenges (user_id, created_at DESC) WHERE status = 'pending';

-- Sessions created by pairing remember the factor, so unpairing a phone signs it out.
ALTER TABLE sessions ADD COLUMN factor_id uuid REFERENCES auth_factors(id) ON DELETE CASCADE;

ALTER TABLE device_pairings ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_pairings USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
ALTER TABLE push_registrations ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON push_registrations USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());

-- The phone has only the pairing code, so resolving it must work before a tenant is known.
CREATE FUNCTION nexus_pairing_lookup(p_code_hash bytea)
RETURNS TABLE (pairing_id uuid, org_id uuid, user_id uuid, session_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p.id, p.org_id, p.user_id, p.session_id FROM device_pairings p
  JOIN users u ON u.id = p.user_id
  WHERE p.code_hash = p_code_hash AND p.used_at IS NULL AND p.expires_at > now() AND u.status = 'active'
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON device_pairings, push_registrations TO nexus_app;
REVOKE ALL ON FUNCTION nexus_pairing_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_pairing_lookup(bytea) TO nexus_app;

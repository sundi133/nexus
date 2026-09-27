-- 0008: devices, enrollment, device-signed check-ins, posture checks, device policies.

-- Tokens an admin (or MDM) uses to enroll devices. Only the hash is stored.
CREATE TABLE device_enrollment_tokens (
  id              uuid PRIMARY KEY,
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name            text NOT NULL,
  token_hash      bytea NOT NULL UNIQUE,
  assign_user_id  uuid REFERENCES users(id) ON DELETE CASCADE, -- personal "enroll my device" tokens
  created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
  max_uses        int,
  uses            int NOT NULL DEFAULT 0,
  expires_at      timestamptz NOT NULL,
  revoked_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
  id                     uuid PRIMARY KEY,
  org_id                 uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  hostname               text NOT NULL,
  platform               text NOT NULL CHECK (platform IN ('macos', 'windows', 'linux')),
  os_name                text NOT NULL DEFAULT '',
  os_version             text NOT NULL DEFAULT '',
  os_build               text NOT NULL DEFAULT '',
  arch                   text NOT NULL DEFAULT '',
  model                  text NOT NULL DEFAULT '',
  serial                 text NOT NULL DEFAULT '',
  agent_version          text NOT NULL DEFAULT '',
  public_jwk             jsonb NOT NULL,          -- device key (P-256); the private key never leaves the device
  key_thumbprint         text NOT NULL UNIQUE,    -- RFC 7638
  primary_user_id        uuid REFERENCES users(id) ON DELETE SET NULL,
  enrollment_token_id    uuid REFERENCES device_enrollment_tokens(id) ON DELETE SET NULL,
  status                 text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
  compliance             text NOT NULL DEFAULT 'unknown' CHECK (compliance IN ('compliant', 'non_compliant', 'unknown')),
  compliance_changed_at  timestamptz,
  inventory              jsonb NOT NULL DEFAULT '{}',
  posture                jsonb NOT NULL DEFAULT '{}',  -- raw facts reported by the agent
  enrolled_at            timestamptz NOT NULL DEFAULT now(),
  last_seen_at           timestamptz,
  last_ip                text NOT NULL DEFAULT '',
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX devices_org ON devices (org_id, id DESC) WHERE status = 'active';
CREATE INDEX devices_user ON devices (primary_user_id) WHERE status = 'active';

-- Result of each policy check on each device (the "why" behind compliance).
CREATE TABLE device_checks (
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  check_key   text NOT NULL,
  status      text NOT NULL CHECK (status IN ('pass', 'fail', 'unknown', 'not_applicable')),
  detail      text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, check_key)
);

-- Organization device policies (DPOL-01/03). Audit-only in Release A; enforcement comes in B.
CREATE TABLE device_policies (
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  check_key   text NOT NULL,
  enabled     boolean NOT NULL DEFAULT true,
  params      jsonb NOT NULL DEFAULT '{}',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, check_key)
);

-- Replay protection for device-signed requests (jti seen within its validity window).
CREATE TABLE agent_nonces (
  jti         text PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX agent_nonces_expiry ON agent_nonces (expires_at);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['device_enrollment_tokens','devices','device_checks','device_policies','agent_nonces']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;

-- Agents authenticate before any tenant is known: resolve the enrollment token / device first.
CREATE FUNCTION nexus_enrollment_lookup(p_token_hash bytea)
RETURNS TABLE (token_id uuid, org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id FROM device_enrollment_tokens
  WHERE token_hash = p_token_hash AND revoked_at IS NULL AND expires_at > now()
    AND (max_uses IS NULL OR uses < max_uses)
$$;

CREATE FUNCTION nexus_device_auth(p_device_id uuid)
RETURNS TABLE (org_id uuid, public_jwk jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, public_jwk FROM devices WHERE id = p_device_id AND status = 'active'
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON device_enrollment_tokens, devices, device_checks, device_policies, agent_nonces TO nexus_app;
REVOKE ALL ON FUNCTION nexus_enrollment_lookup(bytea), nexus_device_auth(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_enrollment_lookup(bytea), nexus_device_auth(uuid) TO nexus_app;

-- 0009: conditional access policies and device-trusted sessions (SPEC CA-01..05).

CREATE TABLE access_policies (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name         text NOT NULL,
  enabled      boolean NOT NULL DEFAULT true,
  mode         text NOT NULL DEFAULT 'report_only' CHECK (mode IN ('report_only', 'enforce')),
  requirement  text NOT NULL CHECK (requirement IN ('require_mfa', 'require_managed_device', 'require_compliant_device', 'block')),
  -- {apps: "all" | uuid[], users: {include: "all" | {groups: uuid[], users: uuid[]}, exclude: {groups: uuid[], users: uuid[]}}}
  conditions   jsonb NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

-- A session can be bound to the device it's running on, proven by the local agent.
ALTER TABLE sessions ADD COLUMN device_id uuid REFERENCES devices(id) ON DELETE SET NULL;
ALTER TABLE sessions ADD COLUMN device_verified_at timestamptz;

-- One-time challenges the local agent signs to prove which device a browser session is on.
CREATE TABLE device_trust_challenges (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  session_id  uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  nonce       text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);

ALTER TABLE access_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON access_policies USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
ALTER TABLE device_trust_challenges ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_trust_challenges USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());

GRANT SELECT, INSERT, UPDATE, DELETE ON access_policies, device_trust_challenges TO nexus_app;

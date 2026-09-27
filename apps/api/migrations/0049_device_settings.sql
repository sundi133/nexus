-- 0049: device settings the agent enforces (firewall, screen lock, BitLocker) and escrow of
-- BitLocker recovery keys. Keys are sealed like every other secret and revealed only with the
-- devices:recovery_keys permission, a recent MFA, and an audit record.
ALTER TABLE devices
  ADD COLUMN settings_report jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN settings_reported_at timestamptz;

CREATE TABLE device_recovery_keys (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  volume      text NOT NULL,
  key_id      text NOT NULL,
  sealed      bytea NOT NULL,
  escrowed_at timestamptz NOT NULL DEFAULT now(),
  -- The device stopped reporting this key (it was rotated or removed): kept, marked, for recovery of old backups.
  retired_at  timestamptz,
  UNIQUE (device_id, volume, key_id)
);
CREATE INDEX device_recovery_keys_org ON device_recovery_keys (org_id);
ALTER TABLE device_recovery_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_recovery_keys USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_recovery_keys TO nexus_app;

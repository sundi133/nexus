-- 0028: device actions (SPEC DEV-09) through signed agent commands (CMD-03) or the device's MDM.

-- Each organization signs agent commands with its own Ed25519 key; agents pin the public key at enrollment.
CREATE TABLE command_keys (
  org_id       uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  public_key   text NOT NULL,        -- base64 (raw 32 bytes)
  private_key  bytea NOT NULL,       -- sealed PKCS#8 PEM
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_commands (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  device_id     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  action        text NOT NULL CHECK (action IN ('refresh', 'lock', 'restart', 'wipe')),
  channel       text NOT NULL CHECK (channel IN ('agent', 'mdm')),
  status        text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'done', 'failed', 'expired', 'canceled')),
  reason        text NOT NULL DEFAULT '',
  output        text NOT NULL DEFAULT '',
  requested_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  sent_at       timestamptz,
  finished_at   timestamptz
);
CREATE INDEX device_commands_pending ON device_commands (device_id) WHERE status IN ('queued', 'sent');
CREATE INDEX device_commands_device ON device_commands (device_id, created_at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['command_keys','device_commands']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON command_keys, device_commands TO nexus_app;

-- Jamf addresses MDM commands by management ID, not inventory ID.
ALTER TABLE mdm_devices ADD COLUMN management_id text NOT NULL DEFAULT '';

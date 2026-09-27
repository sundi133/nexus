-- 0027: device signals from MDMs (Microsoft Intune, Jamf Pro), matched to Nexus devices by serial number.
-- Nexus reads them; an admin can require "managed and compliant in your MDM" as a device policy.

CREATE TABLE mdm_connections (
  id                uuid PRIMARY KEY,
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider          text NOT NULL CHECK (provider IN ('intune', 'jamf')),
  name              text NOT NULL,
  config            jsonb NOT NULL,              -- tenant/client IDs, Jamf URL
  secret            bytea NOT NULL,              -- sealed client secret
  enabled           boolean NOT NULL DEFAULT true,
  interval_minutes  int NOT NULL DEFAULT 60 CHECK (interval_minutes BETWEEN 15 AND 1440),
  last_sync_at      timestamptz,
  last_status       text NOT NULL DEFAULT 'never' CHECK (last_status IN ('never', 'ok', 'error')),
  last_error        text NOT NULL DEFAULT '',
  last_result       jsonb NOT NULL DEFAULT '{}',
  created_by        uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

-- The MDM's view of each device it manages, and which Nexus device that is (if any).
CREATE TABLE mdm_devices (
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  connection_id    uuid NOT NULL REFERENCES mdm_connections(id) ON DELETE CASCADE,
  external_id      text NOT NULL,
  serial           text NOT NULL DEFAULT '',
  name             text NOT NULL DEFAULT '',
  platform         text NOT NULL DEFAULT '',
  os_version       text NOT NULL DEFAULT '',
  user_email       text NOT NULL DEFAULT '',
  managed          boolean NOT NULL DEFAULT true,
  compliant        boolean,                     -- null: the MDM doesn't say
  compliance_detail text NOT NULL DEFAULT '',
  encrypted        boolean,
  last_contact_at  timestamptz,
  device_id        uuid REFERENCES devices(id) ON DELETE SET NULL,
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (connection_id, external_id)
);
CREATE INDEX mdm_devices_serial ON mdm_devices (org_id, lower(serial));
CREATE INDEX mdm_devices_device ON mdm_devices (device_id) WHERE device_id IS NOT NULL;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['mdm_connections','mdm_devices']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON mdm_connections, mdm_devices TO nexus_app;

CREATE FUNCTION nexus_due_mdm_syncs()
RETURNS TABLE (org_id uuid, connection_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM mdm_connections
  WHERE enabled AND (last_sync_at IS NULL OR last_sync_at + make_interval(mins => interval_minutes) <= now())
$$;
REVOKE ALL ON FUNCTION nexus_due_mdm_syncs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_due_mdm_syncs() TO nexus_app;

-- 0061: configuration profiles for Macs enrolled in Nexus MDM (uploaded .mobileconfig, or built
-- from templates), targeted at every Mac or at groups, installed and removed by reconciliation.
CREATE TABLE apple_mdm_profiles (
  id             uuid PRIMARY KEY,
  org_id         uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name           text NOT NULL,
  identifier     text NOT NULL,                  -- the profile's PayloadIdentifier
  payload        bytea NOT NULL,                 -- sealed: profiles can hold Wi-Fi and other secrets
  payload_types  text[] NOT NULL DEFAULT '{}',
  source         text NOT NULL DEFAULT 'upload' CHECK (source IN ('upload', 'template')),
  target         jsonb NOT NULL DEFAULT '{"all": true}',
  created_by     uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, identifier)
);

CREATE TABLE apple_mdm_device_profiles (
  org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  mdm_device_id   uuid NOT NULL REFERENCES apple_mdm_devices (id) ON DELETE CASCADE,
  identifier      text NOT NULL,
  profile_id      uuid REFERENCES apple_mdm_profiles (id) ON DELETE SET NULL,
  status          text NOT NULL CHECK (status IN ('installing', 'installed', 'failed', 'removing')),
  detail          text NOT NULL DEFAULT '',
  command_id      uuid,
  installed_version timestamptz,                -- the profile's updated_at that was sent
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (mdm_device_id, identifier)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['apple_mdm_profiles','apple_mdm_device_profiles']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON apple_mdm_profiles, apple_mdm_device_profiles TO nexus_app;

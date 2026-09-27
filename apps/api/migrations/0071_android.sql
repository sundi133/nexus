-- 0071: Android Enterprise through Google's Android Management API. Nexus is the EMM: it holds
-- the organization's Google Cloud service account (sealed), its Android enterprise, one policy,
-- and a copy of what Google reports about each enrolled device.
CREATE TABLE android_settings (
  org_id            uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  project_id        text NOT NULL DEFAULT '',
  service_account   bytea,                          -- sealed JSON key
  client_email      text NOT NULL DEFAULT '',
  signup_url_name   text NOT NULL DEFAULT '',
  enterprise_name   text NOT NULL DEFAULT '',       -- enterprises/LC0…
  enterprise_display text NOT NULL DEFAULT '',
  policy            jsonb NOT NULL DEFAULT '{}',    -- Nexus's settings the Google policy is built from
  policy_applied_at timestamptz,
  last_sync_at      timestamptz,
  last_error        text NOT NULL DEFAULT '',
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE android_devices (
  id                uuid PRIMARY KEY,
  org_id            uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name              text NOT NULL,                  -- enterprises/…/devices/…
  serial            text NOT NULL DEFAULT '',
  brand             text NOT NULL DEFAULT '',
  model             text NOT NULL DEFAULT '',
  android_version   text NOT NULL DEFAULT '',
  security_patch    text NOT NULL DEFAULT '',
  management_mode   text NOT NULL DEFAULT '',       -- DEVICE_OWNER (company) or PROFILE_OWNER (work profile)
  ownership         text NOT NULL DEFAULT '',
  state             text NOT NULL DEFAULT '',
  policy_compliant  boolean,
  non_compliance    jsonb NOT NULL DEFAULT '[]',
  assigned_user_id  uuid REFERENCES users (id) ON DELETE SET NULL,
  enrolled_at       timestamptz,
  last_status_at    timestamptz,
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['android_settings','android_devices']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON android_settings, android_devices TO nexus_app;

-- The hourly device sync reaches every connected organization.
CREATE FUNCTION nexus_android_orgs()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM android_settings WHERE enterprise_name <> '' AND service_account IS NOT NULL
$$;
REVOKE ALL ON FUNCTION nexus_android_orgs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_android_orgs() TO nexus_app;

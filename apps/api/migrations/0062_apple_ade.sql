-- 0062: zero-touch enrollment through Apple Business Manager (Automated Device Enrollment). Nexus
-- holds the key the ABM server token is encrypted to, syncs the Macs assigned to it, and assigns
-- them its enrollment profile; in Setup Assistant a Mac fetches it from its own org's URL.
CREATE TABLE apple_ade_settings (
  org_id            uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  key               bytea NOT NULL,                -- sealed: the private key ABM encrypts the token to
  cert              text NOT NULL,                 -- its certificate, uploaded to ABM
  token             bytea,                         -- sealed: the decrypted server token (OAuth credentials)
  token_expires_at  timestamptz,
  server_name       text NOT NULL DEFAULT '',
  abm_org_name      text NOT NULL DEFAULT '',
  enroll_secret     text NOT NULL UNIQUE,          -- the unguessable part of this org's enrollment URL
  profile_uuid      text,
  profile           jsonb NOT NULL DEFAULT '{}',
  auto_assign       boolean NOT NULL DEFAULT true,
  cursor            text,
  last_sync_at      timestamptz,
  last_error        text NOT NULL DEFAULT '',
  updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE apple_ade_devices (
  org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  serial          text NOT NULL,
  model           text NOT NULL DEFAULT '',
  description     text NOT NULL DEFAULT '',
  color           text NOT NULL DEFAULT '',
  os              text NOT NULL DEFAULT '',
  profile_status  text NOT NULL DEFAULT '',
  profile_uuid    text NOT NULL DEFAULT '',
  assigned_at     timestamptz,
  deleted         boolean NOT NULL DEFAULT false,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, serial)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['apple_ade_settings','apple_ade_devices']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON apple_ade_settings, apple_ade_devices TO nexus_app;

-- A Mac in Setup Assistant calls without a tenant: find the org from its enrollment URL.
CREATE FUNCTION nexus_apple_ade_org(p_secret text)
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM apple_ade_settings WHERE enroll_secret = p_secret AND token IS NOT NULL
$$;
-- The hourly sync reaches every connected org.
CREATE FUNCTION nexus_apple_ade_orgs()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM apple_ade_settings WHERE token IS NOT NULL
$$;
REVOKE ALL ON FUNCTION nexus_apple_ade_org(text), nexus_apple_ade_orgs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_apple_ade_org(text), nexus_apple_ade_orgs() TO nexus_app;

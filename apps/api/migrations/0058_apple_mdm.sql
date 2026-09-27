-- 0058: Nexus as an Apple MDM server (macOS). Macs enroll with a profile that carries a
-- per-device identity (issued by the organization's own CA); every check-in is signed with it
-- (Mdm-Signature). Commands wait in a queue and devices are woken with APNs, using the push
-- certificate the organization gets from Apple.
CREATE TABLE apple_mdm_settings (
  org_id           uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  ca_cert          text NOT NULL,
  ca_key           bytea NOT NULL,          -- sealed
  push_key         bytea,                   -- sealed: the key of the push certificate in use
  push_key_pending bytea,                   -- sealed: the key of a CSR not yet answered (first setup or renewal)
  push_csr         text,
  push_cert        text,
  push_topic       text,                    -- com.apple.mgmt.External.<uuid>, from the certificate
  push_expires_at  timestamptz,
  updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE apple_mdm_enroll_links (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name        text NOT NULL,
  token_hash  bytea NOT NULL UNIQUE,
  uses        int NOT NULL DEFAULT 0,
  created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz
);

-- Every device identity Nexus issued: a check-in is trusted only when signed by one of these.
CREATE TABLE apple_mdm_identities (
  fingerprint  text PRIMARY KEY,              -- SHA-256 of the certificate
  org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  link_id      uuid REFERENCES apple_mdm_enroll_links (id) ON DELETE SET NULL,
  issued_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE apple_mdm_devices (
  id               uuid PRIMARY KEY,
  org_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  udid             text NOT NULL,
  identity_fp      text NOT NULL,
  serial           text NOT NULL DEFAULT '',
  model            text NOT NULL DEFAULT '',
  device_name      text NOT NULL DEFAULT '',
  os_version       text NOT NULL DEFAULT '',
  topic            text NOT NULL DEFAULT '',
  push_token       text,
  push_magic       text,
  unlock_token     bytea,                     -- sealed
  bootstrap_token  bytea,                     -- sealed
  status           text NOT NULL DEFAULT 'authenticated' CHECK (status IN ('authenticated', 'enrolled', 'checked_out')),
  device_id        uuid REFERENCES devices (id) ON DELETE SET NULL, -- the same Mac's Nexus agent, by serial
  info             jsonb NOT NULL DEFAULT '{}',
  security         jsonb NOT NULL DEFAULT '{}',
  enrolled_at      timestamptz,
  last_seen_at     timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, udid)
);

CREATE TABLE apple_mdm_commands (
  id              uuid PRIMARY KEY,           -- the CommandUUID
  org_id          uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  mdm_device_id   uuid NOT NULL REFERENCES apple_mdm_devices (id) ON DELETE CASCADE,
  request_type    text NOT NULL,
  command         jsonb NOT NULL,
  status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'acknowledged', 'error', 'notnow', 'canceled')),
  result          jsonb,
  error           text NOT NULL DEFAULT '',
  reason          text NOT NULL DEFAULT '',
  requested_by    uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  sent_at         timestamptz,
  finished_at     timestamptz
);
CREATE INDEX apple_mdm_commands_next ON apple_mdm_commands (mdm_device_id, created_at) WHERE status IN ('queued', 'notnow');

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['apple_mdm_settings','apple_mdm_enroll_links','apple_mdm_identities','apple_mdm_devices','apple_mdm_commands']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON apple_mdm_settings, apple_mdm_enroll_links, apple_mdm_identities, apple_mdm_devices, apple_mdm_commands TO nexus_app;

-- Devices call without a tenant: these narrow lookups find which organization a request is for.
CREATE FUNCTION nexus_apple_mdm_link(p_hash bytea)
RETURNS TABLE (org_id uuid, link_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM apple_mdm_enroll_links WHERE token_hash = p_hash AND revoked_at IS NULL AND expires_at > now()
$$;
CREATE FUNCTION nexus_apple_mdm_identity(p_fingerprint text)
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM apple_mdm_identities WHERE fingerprint = p_fingerprint
$$;
REVOKE ALL ON FUNCTION nexus_apple_mdm_link(bytea), nexus_apple_mdm_identity(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_apple_mdm_link(bytea), nexus_apple_mdm_identity(text) TO nexus_app;

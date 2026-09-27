-- 0012: directory sync from Google Workspace and Microsoft Entra ID (SPEC DIR-08).

CREATE TABLE directory_connections (
  id                 uuid PRIMARY KEY,
  org_id             uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider           text NOT NULL CHECK (provider IN ('google', 'entra')),
  name               text NOT NULL,
  config             jsonb NOT NULL,            -- non-secret settings (tenant ID, admin email, …)
  secret             bytea NOT NULL,            -- sealed credential (service account key / client secret)
  enabled            boolean NOT NULL DEFAULT true,
  sync_groups        boolean NOT NULL DEFAULT true,
  group_filter       text[] NOT NULL DEFAULT '{}', -- remote group IDs; empty = whole directory
  deprovision        text NOT NULL DEFAULT 'suspend' CHECK (deprovision IN ('suspend', 'none')),
  invite_new_users   boolean NOT NULL DEFAULT true,
  interval_minutes   int NOT NULL DEFAULT 60 CHECK (interval_minutes BETWEEN 15 AND 1440),
  last_sync_at       timestamptz,
  last_status        text NOT NULL DEFAULT 'never' CHECK (last_status IN ('never', 'ok', 'error', 'needs_approval')),
  last_result        jsonb NOT NULL DEFAULT '{}',
  last_error         text NOT NULL DEFAULT '',
  created_by         uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

-- Which local user/group each remote object is, and whether sync suspended it
-- (so sync only ever reactivates what sync suspended, never an admin's suspension).
CREATE TABLE directory_links (
  org_id             uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  connection_id      uuid NOT NULL REFERENCES directory_connections(id) ON DELETE CASCADE,
  kind               text NOT NULL CHECK (kind IN ('user', 'group')),
  external_id        text NOT NULL,
  local_id           uuid NOT NULL,
  suspended_by_sync  boolean NOT NULL DEFAULT false,
  PRIMARY KEY (connection_id, kind, external_id),
  UNIQUE (connection_id, kind, local_id)
);
CREATE INDEX directory_links_local ON directory_links (org_id, kind, local_id);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['directory_connections','directory_links']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON directory_connections, directory_links TO nexus_app;

-- The scheduler serves every tenant: which connections are due for a sync.
CREATE FUNCTION nexus_due_directory_syncs()
RETURNS TABLE (org_id uuid, connection_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM directory_connections
  WHERE enabled AND (last_sync_at IS NULL OR last_sync_at + make_interval(mins => interval_minutes) <= now())
$$;
REVOKE ALL ON FUNCTION nexus_due_directory_syncs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_due_directory_syncs() TO nexus_app;

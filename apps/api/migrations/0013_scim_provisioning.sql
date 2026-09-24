-- 0013: outbound SCIM 2.0 provisioning to apps (SPEC SCIM-01/02).

CREATE TABLE app_provisioning (
  app_id                uuid PRIMARY KEY REFERENCES applications(id) ON DELETE CASCADE,
  org_id                uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  enabled               boolean NOT NULL DEFAULT false,
  base_url              text NOT NULL,
  token                 bytea NOT NULL,            -- sealed bearer token
  push_groups           boolean NOT NULL DEFAULT true,
  on_unassign           text NOT NULL DEFAULT 'deactivate' CHECK (on_unassign IN ('deactivate', 'delete')),
  last_error            text NOT NULL DEFAULT '',
  last_error_at         timestamptz,
  last_success_at       timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);

-- The app-side account for each person (its SCIM id) and how the last push went.
CREATE TABLE provisioned_accounts (
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  app_id          uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  remote_id       text,
  state           text NOT NULL CHECK (state IN ('active', 'inactive', 'error')),
  attrs_hash      text NOT NULL DEFAULT '',  -- what we last sent, to skip no-op updates
  last_error      text NOT NULL DEFAULT '',
  last_synced_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, user_id)
);

CREATE TABLE provisioned_groups (
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  app_id          uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  group_id        uuid NOT NULL,             -- no FK: the row must outlive the group so it can be deleted upstream
  remote_id       text NOT NULL,
  display_name    text NOT NULL,
  last_synced_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (app_id, group_id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['app_provisioning','provisioned_accounts','provisioned_groups']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON app_provisioning, provisioned_accounts, provisioned_groups TO nexus_app;

-- Periodic reconcile (catches anything a trigger missed): every enabled app, every tenant.
CREATE FUNCTION nexus_provisioned_apps()
RETURNS TABLE (org_id uuid, app_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, app_id FROM app_provisioning WHERE enabled
$$;
REVOKE ALL ON FUNCTION nexus_provisioned_apps() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_provisioned_apps() TO nexus_app;

-- 0036: RBAC v2 (SPEC RBAC-02, RBAC-03). Custom roles are named sets of catalog permissions.
-- Role grants give a person a custom role, or a built-in role limited to some groups
-- (e.g. Help Desk for "EMEA" only). Org-wide built-in roles stay in user_roles.

CREATE TABLE custom_roles (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name         text NOT NULL,
  description  text NOT NULL DEFAULT '',
  permissions  text[] NOT NULL CHECK (cardinality(permissions) > 0),
  created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE role_grants (
  id               uuid PRIMARY KEY,
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  builtin_role     text CHECK (builtin_role IN ('helpdesk', 'security_analyst', 'readonly')),
  custom_role_id   uuid REFERENCES custom_roles(id) ON DELETE CASCADE,
  scope_group_ids  uuid[] NOT NULL DEFAULT '{}',   -- empty: the whole organization
  created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  CHECK ((builtin_role IS NULL) <> (custom_role_id IS NULL)),
  -- A built-in role for the whole organization is a user_roles row, not a grant.
  CHECK (builtin_role IS NULL OR cardinality(scope_group_ids) > 0)
);
CREATE UNIQUE INDEX role_grants_one ON role_grants (user_id, coalesce(builtin_role, custom_role_id::text));
CREATE INDEX role_grants_user ON role_grants (user_id);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['custom_roles','role_grants']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON custom_roles, role_grants TO nexus_app;

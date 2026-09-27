-- 0059: requests for apps on devices. People can ask for an exception to a block rule (when the
-- agent stops an app) or for software from the App deployment catalog, through the same access
-- requests, approvals and expiry as apps, groups and admin roles.
ALTER TABLE access_catalog DROP CONSTRAINT access_catalog_resource_type_check;
ALTER TABLE access_catalog ADD CONSTRAINT access_catalog_resource_type_check CHECK (resource_type IN ('app', 'group', 'role', 'block_exception', 'software'));

-- A block rule that doesn't apply to one person's devices (granted by an approved request).
CREATE TABLE enforcement_exceptions (
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  rule_id     uuid NOT NULL REFERENCES enforcement_rules (id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  request_id  uuid REFERENCES access_requests (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (rule_id, user_id)
);
ALTER TABLE enforcement_exceptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON enforcement_exceptions USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON enforcement_exceptions TO nexus_app;

-- Software for one person's devices (an approved request), besides everyone or a group.
ALTER TABLE software_assignments ADD COLUMN user_id uuid REFERENCES users (id) ON DELETE CASCADE;
ALTER TABLE software_assignments ADD CONSTRAINT software_assignments_one_target CHECK (group_id IS NULL OR user_id IS NULL);
DROP INDEX software_assignments_unique;
CREATE UNIQUE INDEX software_assignments_unique ON software_assignments (package_id, COALESCE(group_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(user_id, '00000000-0000-0000-0000-000000000000'::uuid));

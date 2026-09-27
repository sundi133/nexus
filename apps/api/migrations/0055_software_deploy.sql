-- 0055: app deployment (like JumpCloud Software Management). A catalog of packages, assignments
-- that install or remove them on everyone's or a group's devices, and each device's state. The
-- agent gets its apps in the signed device policy and reports back.
CREATE TABLE software_packages (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name        text NOT NULL,
  description text NOT NULL DEFAULT '',
  platform    text NOT NULL CHECK (platform IN ('macos', 'windows', 'linux')),
  kind        text NOT NULL CHECK (kind IN ('winget', 'msi', 'pkg', 'apt', 'dnf')),
  ref         text NOT NULL,                -- winget ID, MSI ProductCode, pkg receipt ID, package name
  url         text NOT NULL DEFAULT '',     -- msi / pkg: where the installer is (https)
  sha256      text NOT NULL DEFAULT '',     -- …and its hash, checked by the agent
  args        jsonb NOT NULL DEFAULT '[]',
  created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE software_assignments (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  package_id  uuid NOT NULL REFERENCES software_packages (id) ON DELETE CASCADE,
  action      text NOT NULL CHECK (action IN ('install', 'remove')),
  group_id    uuid REFERENCES groups (id) ON DELETE CASCADE, -- NULL: every device on the platform
  created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX software_assignments_unique ON software_assignments (package_id, COALESCE(group_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE TABLE device_software (
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  package_id  uuid NOT NULL REFERENCES software_packages (id) ON DELETE CASCADE,
  status      text NOT NULL CHECK (status IN ('installed', 'absent', 'failed', 'unsupported')),
  detail      text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, package_id)
);
CREATE INDEX device_software_package ON device_software (package_id, status);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['software_packages','software_assignments','device_software']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON software_packages, software_assignments, device_software TO nexus_app;

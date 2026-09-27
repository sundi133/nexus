-- 0029: access requests with approvals and automatic expiry (SPEC JIT-01/02/04), including
-- just-in-time admin roles (OPS-11). People request an app, a group or an admin role with a
-- reason and a duration; approvers decide in stages; the grant ends by itself.

-- Who someone's manager is (approval stage "manager"). Set by admins or SCIM (enterprise extension).
ALTER TABLE users ADD COLUMN manager_id uuid REFERENCES users(id) ON DELETE SET NULL;

-- What can be requested, and how it's approved.
CREATE TABLE access_catalog (
  id             uuid PRIMARY KEY,
  org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  resource_type  text NOT NULL CHECK (resource_type IN ('app', 'group', 'role')),
  resource_id    uuid,                                 -- the app or group
  role           text,                                 -- the admin role (never owner)
  description    text NOT NULL DEFAULT '',
  enabled        boolean NOT NULL DEFAULT true,
  max_hours      int NOT NULL DEFAULT 168 CHECK (max_hours BETWEEN 1 AND 8760),
  allow_permanent boolean NOT NULL DEFAULT false,      -- apps and groups: may be granted without an end
  stages         jsonb NOT NULL DEFAULT '[]',          -- [{kind: manager|users|group|role, ids?|id?|role?}] in order
  eligible       jsonb NOT NULL DEFAULT '{"users":[],"groups":[]}', -- pre-approved: activate with MFA and a reason
  created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  CHECK ((resource_type = 'role') = (role IS NOT NULL AND resource_id IS NULL)),
  CHECK (role IS NULL OR role IN ('admin', 'helpdesk', 'security_analyst', 'readonly'))
);
CREATE UNIQUE INDEX access_catalog_resource ON access_catalog (org_id, resource_type, coalesce(resource_id::text, role));

CREATE TABLE access_requests (
  id              uuid PRIMARY KEY,
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  catalog_id      uuid NOT NULL REFERENCES access_catalog(id) ON DELETE CASCADE,
  requester_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  justification   text NOT NULL,
  duration_hours  int,                                  -- null: permanent (when allowed)
  status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'denied', 'canceled', 'ended', 'revoked')),
  stage           int NOT NULL DEFAULT 0,               -- the approval stage it's waiting on
  auto_approved   boolean NOT NULL DEFAULT false,       -- eligible requester (pre-approved)
  granted_at      timestamptz,
  expires_at      timestamptz,
  ended_at        timestamptz,
  end_reason      text NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX access_requests_requester ON access_requests (requester_id, created_at DESC);
CREATE INDEX access_requests_pending ON access_requests (org_id, status) WHERE status = 'pending';
CREATE INDEX access_requests_expiry ON access_requests (expires_at) WHERE status = 'active' AND expires_at IS NOT NULL;
-- One open request per person and resource.
CREATE UNIQUE INDEX access_requests_open ON access_requests (catalog_id, requester_id) WHERE status IN ('pending', 'active');

CREATE TABLE access_decisions (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  request_id   uuid NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
  stage        int NOT NULL,
  approver_id  uuid REFERENCES users(id) ON DELETE SET NULL,
  decision     text NOT NULL CHECK (decision IN ('approve', 'deny')),
  comment      text NOT NULL DEFAULT '',
  at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX access_decisions_request ON access_decisions (request_id, stage);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['access_catalog','access_requests','access_decisions']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON access_catalog, access_requests, access_decisions TO nexus_app;

-- Grants that have run out (every tenant), for the expiry sweep.
CREATE FUNCTION nexus_access_grants_expired()
RETURNS TABLE (org_id uuid, request_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM access_requests WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= now() LIMIT 500
$$;
REVOKE ALL ON FUNCTION nexus_access_grants_expired() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_access_grants_expired() TO nexus_app;

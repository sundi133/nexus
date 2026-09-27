-- 0019: verified email domains (SPEC ORG-02).

CREATE TABLE org_domains (
  id               uuid PRIMARY KEY,
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain           text NOT NULL CHECK (domain = lower(domain)),
  token            text NOT NULL,
  status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failing')),
  verified_at      timestamptz,
  last_checked_at  timestamptz,
  failing_since    timestamptz,
  last_error       text NOT NULL DEFAULT '',
  created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, domain)
);
-- A domain belongs to at most one organization once proven (across all tenants).
CREATE UNIQUE INDEX org_domains_claimed ON org_domains (domain) WHERE status IN ('verified', 'failing');

ALTER TABLE org_domains ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON org_domains USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON org_domains TO nexus_app;

-- Which organization (if any) has proven this domain. Used before a tenant is known (signup)
-- and across tenants (another org can't add people from a domain it doesn't own).
CREATE FUNCTION nexus_domain_claimed_by(p_domain text)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM org_domains WHERE domain = lower(p_domain) AND status IN ('verified', 'failing') LIMIT 1
$$;

CREATE FUNCTION nexus_domains_to_recheck()
RETURNS TABLE (org_id uuid, domain_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM org_domains
  WHERE status IN ('verified', 'failing') AND (last_checked_at IS NULL OR last_checked_at < now() - interval '24 hours')
$$;

REVOKE ALL ON FUNCTION nexus_domain_claimed_by(text), nexus_domains_to_recheck() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_domain_claimed_by(text), nexus_domains_to_recheck() TO nexus_app;

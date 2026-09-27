-- 0015: scoped, expiring API keys for automation (SPEC INT-02).

CREATE TABLE api_keys (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name          text NOT NULL,
  prefix        text NOT NULL,              -- first characters, to recognize a key without storing it
  key_hash      bytea NOT NULL UNIQUE,
  scopes        text[] NOT NULL,
  created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  expires_at    timestamptz NOT NULL,
  last_used_at  timestamptz,
  last_used_ip  text NOT NULL DEFAULT '',
  revoked_at    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_keys_org ON api_keys (org_id, created_at DESC);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON api_keys USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO nexus_app;

-- Authenticating a key happens before the tenant is known.
CREATE FUNCTION nexus_auth_api_key(p_hash bytea)
RETURNS TABLE (id uuid, org_id uuid, name text, scopes text[], created_by uuid, last_used_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id, name, scopes, created_by, last_used_at FROM api_keys
  WHERE key_hash = p_hash AND revoked_at IS NULL AND expires_at > now()
$$;
REVOKE ALL ON FUNCTION nexus_auth_api_key(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_auth_api_key(bytea) TO nexus_app;

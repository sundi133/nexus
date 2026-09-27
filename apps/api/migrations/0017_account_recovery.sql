-- 0017: account recovery (SPEC AUTH-02 recovery codes, AUTH-08 self-service reset).

CREATE TABLE recovery_codes (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash   bytea NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id) WHERE used_at IS NULL;

CREATE TABLE password_resets (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  bytea NOT NULL UNIQUE,
  ip          text NOT NULL DEFAULT '',
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['recovery_codes','password_resets']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_codes, password_resets TO nexus_app;

-- A reset link is used before any tenant is known.
CREATE FUNCTION nexus_password_reset_lookup(p_hash bytea)
RETURNS TABLE (reset_id uuid, org_id uuid, user_id uuid, email text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT r.id, r.org_id, r.user_id, u.email FROM password_resets r JOIN users u ON u.id = r.user_id
  WHERE r.token_hash = p_hash AND r.used_at IS NULL AND r.expires_at > now() AND u.status IN ('active', 'staged')
$$;
REVOKE ALL ON FUNCTION nexus_password_reset_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_password_reset_lookup(bytea) TO nexus_app;

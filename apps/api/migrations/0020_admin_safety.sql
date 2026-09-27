-- 0020: admin safety (SPEC RBAC-04 owners use passkeys, RBAC-05 break-glass accounts).

-- How the session last proved MFA (the owner-passkey rule needs to know).
ALTER TABLE sessions ADD COLUMN mfa_method text CHECK (mfa_method IN ('totp', 'push', 'webauthn', 'recovery_code'));

-- An emergency owner account: exempt from anything that could lock everyone out, and loud when used.
ALTER TABLE users ADD COLUMN break_glass boolean NOT NULL DEFAULT false;

DROP FUNCTION nexus_auth_session(bytea);
CREATE FUNCTION nexus_auth_session(p_token_hash bytea)
RETURNS TABLE (session_id uuid, org_id uuid, user_id uuid, state text, client text,
               mfa_at timestamptz, mfa_method text, expires_at timestamptz, user_status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT s.id, s.org_id, s.user_id, s.state, s.client, s.mfa_at, s.mfa_method, s.expires_at, u.status
  FROM sessions s JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL AND s.expires_at > now()
$$;
REVOKE ALL ON FUNCTION nexus_auth_session(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_auth_session(bytea) TO nexus_app;

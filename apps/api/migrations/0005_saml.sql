-- 0005: SAML signing certificates share the signing_keys table, tagged by purpose.
ALTER TABLE signing_keys ADD COLUMN purpose text NOT NULL DEFAULT 'oidc' CHECK (purpose IN ('oidc', 'saml'));
ALTER TABLE signing_keys ADD COLUMN cert_pem text;       -- X.509 certificate (SAML only)
ALTER TABLE signing_keys ADD COLUMN not_after timestamptz;
DROP INDEX signing_keys_org;
CREATE INDEX signing_keys_org ON signing_keys (org_id, purpose, status);

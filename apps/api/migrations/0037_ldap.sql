-- 0037: Active Directory / LDAP directory connections (on-prem directories). The LDAP
-- settings live in config and the service account's password in the sealed secret, like
-- the other pulled directories; config.password_auth turns on sign-in with the directory
-- password (delegated authentication).
ALTER TABLE directory_connections DROP CONSTRAINT directory_connections_provider_check;
ALTER TABLE directory_connections ADD CONSTRAINT directory_connections_provider_check CHECK (provider IN ('google', 'entra', 'scim', 'ldap'));

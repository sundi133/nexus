-- 0052: Nexus as an LDAP directory and a RADIUS server, for what can't do SAML or OIDC: legacy
-- apps, NAS boxes and printers (LDAP), VPNs and Wi-Fi (RADIUS). Both are off until an admin
-- turns them on for the organization.
CREATE TABLE directory_service_settings (
  org_id         uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  ldap_enabled   boolean NOT NULL DEFAULT false,
  radius_enabled boolean NOT NULL DEFAULT false,
  radius_mfa     text NOT NULL DEFAULT 'if_enrolled' CHECK (radius_mfa IN ('required', 'if_enrolled', 'off')),
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Apps bind as a service account to search the directory: cn=<name>,ou=services,o=<org>,dc=nexus
CREATE TABLE ldap_service_accounts (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name         text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  secret_hash  text NOT NULL,
  created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);
CREATE UNIQUE INDEX ldap_service_accounts_name ON ldap_service_accounts (org_id, name) WHERE revoked_at IS NULL;

-- RADIUS clients (VPN concentrators, Wi-Fi controllers): known by source address. The shared
-- secret is sealed, not hashed: RADIUS needs it to check and sign every packet.
CREATE TABLE radius_clients (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name         text NOT NULL,
  address      cidr NOT NULL,
  secret       bytea NOT NULL,
  created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz,
  -- An address belongs to one client of one organization: requests are matched by it.
  EXCLUDE USING gist (address inet_ops WITH &&) WHERE (revoked_at IS NULL)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['directory_service_settings','ldap_service_accounts','radius_clients']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON directory_service_settings, ldap_service_accounts, radius_clients TO nexus_app;

-- A RADIUS request's organization and client, from where it came from (cross-tenant by nature).
CREATE FUNCTION nexus_radius_client_for(p_ip inet)
RETURNS TABLE (org_id uuid, client_id uuid, name text, secret bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.org_id, c.id, c.name, c.secret FROM radius_clients c
  JOIN directory_service_settings s ON s.org_id = c.org_id AND s.radius_enabled
  WHERE c.revoked_at IS NULL AND p_ip <<= c.address
  LIMIT 1
$$;
REVOKE ALL ON FUNCTION nexus_radius_client_for(inet) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_radius_client_for(inet) TO nexus_app;

-- Retention: nothing new (binds and authentications are audit events).

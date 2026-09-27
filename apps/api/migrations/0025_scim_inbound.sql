-- 0025: inbound SCIM 2.0 (SPEC DIR-07): Okta, Entra ID and other IdPs push users and groups into Nexus.
-- A SCIM source is a directory connection of provider 'scim': same links, deprovisioning and
-- invitation settings as a synced directory, but the IdP calls us, with a bearer token (stored hashed).

ALTER TABLE directory_connections DROP CONSTRAINT directory_connections_provider_check;
ALTER TABLE directory_connections ADD CONSTRAINT directory_connections_provider_check CHECK (provider IN ('google', 'entra', 'scim'));
ALTER TABLE directory_connections ALTER COLUMN secret DROP NOT NULL;
ALTER TABLE directory_connections ADD CONSTRAINT directory_connections_secret_check CHECK (provider = 'scim' OR secret IS NOT NULL);
ALTER TABLE directory_connections
  ADD COLUMN token_hash                  bytea,           -- SHA-256 of the SCIM bearer token
  ADD COLUMN token_hint                  text NOT NULL DEFAULT '', -- last characters, to recognise it
  ADD COLUMN last_request_at             timestamptz,
  ADD COLUMN deactivations_allowed_until timestamptz;    -- an admin let a burst of deactivations through
CREATE UNIQUE INDEX directory_connections_token ON directory_connections (token_hash) WHERE token_hash IS NOT NULL;

-- Scheduled syncs are for directories we pull from; SCIM sources push.
CREATE OR REPLACE FUNCTION nexus_due_directory_syncs()
RETURNS TABLE (org_id uuid, connection_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM directory_connections
  WHERE enabled AND provider <> 'scim'
    AND (last_sync_at IS NULL OR last_sync_at + make_interval(mins => interval_minutes) <= now())
$$;

-- Which organization and SCIM source a bearer token belongs to (before a tenant is known).
CREATE FUNCTION nexus_scim_auth(p_token_hash bytea)
RETURNS TABLE (org_id uuid, connection_id uuid, enabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id, enabled FROM directory_connections WHERE token_hash = p_token_hash AND provider = 'scim'
$$;
REVOKE ALL ON FUNCTION nexus_scim_auth(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_scim_auth(bytea) TO nexus_app;

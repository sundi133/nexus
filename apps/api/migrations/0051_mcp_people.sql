-- 0051: people's own MCP clients (Cursor, Claude Desktop, VS Code…) through the gateway.
-- Clients register themselves (RFC 7591) and people sign in through Nexus (authorization code +
-- PKCE); tool permissions can name people, groups or everyone; tool calls pass through data
-- protection.

-- Rules can be about people now, not only agents. subject_id names an agent, a person or a
-- group, so one foreign key can't cover it: deleting any of them removes its rules by trigger,
-- as the foreign key did for agents.
ALTER TABLE mcp_permissions DROP CONSTRAINT mcp_permissions_subject_id_fkey;
CREATE FUNCTION nexus_mcp_permissions_cascade() RETURNS trigger
LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
  DELETE FROM mcp_permissions WHERE subject_type = TG_ARGV[0] AND subject_id = OLD.id;
  RETURN OLD;
END
$$;
CREATE TRIGGER mcp_permissions_agent_gone AFTER DELETE ON ai_agents FOR EACH ROW EXECUTE FUNCTION nexus_mcp_permissions_cascade('agent');
CREATE TRIGGER mcp_permissions_user_gone AFTER DELETE ON users FOR EACH ROW EXECUTE FUNCTION nexus_mcp_permissions_cascade('user');
CREATE TRIGGER mcp_permissions_group_gone AFTER DELETE ON groups FOR EACH ROW EXECUTE FUNCTION nexus_mcp_permissions_cascade('group');
ALTER TABLE mcp_permissions DROP CONSTRAINT mcp_permissions_check, DROP CONSTRAINT mcp_permissions_subject_type_check;
ALTER TABLE mcp_permissions
  ADD CONSTRAINT mcp_permissions_subject_type_check CHECK (subject_type IN ('all_agents', 'agent', 'agent_tag', 'all_people', 'user', 'group')),
  ADD CONSTRAINT mcp_permissions_subject_id_check CHECK ((subject_type IN ('agent', 'user', 'group')) = (subject_id IS NOT NULL));

-- MCP clients that registered themselves: public clients (PKCE, no secret), loopback or app-scheme redirects only.
CREATE TABLE mcp_clients (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  client_id     text NOT NULL UNIQUE,
  name          text NOT NULL,
  redirect_uris text[] NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);
CREATE INDEX mcp_clients_org ON mcp_clients (org_id);

-- A person's authorization of a client for the gateway: the refresh token, rotated on each use.
CREATE TABLE mcp_grants (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  client_id     uuid NOT NULL REFERENCES mcp_clients (id) ON DELETE CASCADE,
  resource      text NOT NULL,
  refresh_hash  bytea NOT NULL UNIQUE,
  previous_hash bytea,          -- presenting this again means the token was copied: the grant is revoked
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz
);
CREATE INDEX mcp_grants_user ON mcp_grants (user_id);
CREATE INDEX mcp_grants_previous ON mcp_grants (previous_hash) WHERE previous_hash IS NOT NULL;

-- Codes are for an SSO app or an MCP client.
ALTER TABLE oidc_codes
  ALTER COLUMN app_id DROP NOT NULL,
  ADD COLUMN mcp_client_id uuid REFERENCES mcp_clients (id) ON DELETE CASCADE,
  ADD COLUMN resource text,
  ADD CONSTRAINT oidc_codes_one_client CHECK ((app_id IS NULL) <> (mcp_client_id IS NULL));

-- What tool calls may carry: detectors for arguments (off | monitor | block) and results (off | monitor | redact).
CREATE TABLE mcp_dlp_policies (
  org_id     uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  arguments  jsonb NOT NULL DEFAULT '{}',
  results    jsonb NOT NULL DEFAULT '{}',
  custom     jsonb NOT NULL DEFAULT '[]',
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES users (id) ON DELETE SET NULL
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['mcp_clients','mcp_grants','mcp_dlp_policies']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_clients, mcp_grants, mcp_dlp_policies TO nexus_app;

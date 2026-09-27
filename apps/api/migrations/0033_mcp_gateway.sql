-- 0033: MCP gateway (SPEC MCP-01/02/04/07/08/10). Upstream MCP servers (streamable HTTP)
-- are registered with credentials agents never see; their tools are discovered, classified
-- by risk and approved before use (and again when they change); rules decide which agents
-- may call which tools, with which arguments.

CREATE TABLE mcp_servers (
  id                 uuid PRIMARY KEY,
  org_id             uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name               text NOT NULL,
  slug               text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
  description        text NOT NULL DEFAULT '',
  url                text NOT NULL,
  auth_kind          text NOT NULL DEFAULT 'none' CHECK (auth_kind IN ('none', 'bearer', 'header')),
  auth_header        text NOT NULL DEFAULT '',
  secret             bytea,                        -- sealed; AAD mcp-server:<id>
  status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  auto_approve_read  boolean NOT NULL DEFAULT false,
  calls_per_minute   int NOT NULL DEFAULT 120 CHECK (calls_per_minute BETWEEN 1 AND 10000), -- per agent
  server_info        jsonb NOT NULL DEFAULT '{}',
  last_synced_at     timestamptz,
  last_sync_error    text NOT NULL DEFAULT '',
  created_by         uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, slug),
  UNIQUE (org_id, name),
  CHECK ((auth_kind = 'none') = (secret IS NULL))
);

CREATE TABLE mcp_tools (
  id                 uuid PRIMARY KEY,
  org_id             uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  server_id          uuid NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
  name               text NOT NULL,
  title              text NOT NULL DEFAULT '',
  description        text NOT NULL DEFAULT '',
  input_schema       jsonb NOT NULL DEFAULT '{}',
  annotations        jsonb NOT NULL DEFAULT '{}',
  hash               text NOT NULL,                -- of description, schema and annotations
  status             text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'blocked', 'removed')),
  change             text NOT NULL DEFAULT 'new' CHECK (change IN ('new', 'changed', '')),
  approved_hash      text,
  approved_snapshot  jsonb,                        -- what was approved, to show what changed
  approved_by        uuid REFERENCES users(id) ON DELETE SET NULL,
  approved_at        timestamptz,
  risk               text NOT NULL CHECK (risk IN ('read', 'write', 'external', 'destructive')),
  risk_source        text NOT NULL DEFAULT 'heuristic' CHECK (risk_source IN ('heuristic', 'annotations', 'admin')),
  first_seen_at      timestamptz NOT NULL DEFAULT now(),
  changed_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (server_id, name)
);

CREATE TABLE mcp_permissions (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  server_id     uuid NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
  effect        text NOT NULL CHECK (effect IN ('allow', 'deny')),
  subject_type  text NOT NULL CHECK (subject_type IN ('all_agents', 'agent', 'agent_tag')),
  subject_id    uuid REFERENCES ai_agents(id) ON DELETE CASCADE,
  subject_tag   text,
  tools         text[] NOT NULL,                   -- tool names, or {*} for every approved tool
  risks         text[],                            -- null: any; else only tools of these risk classes
  conditions    jsonb NOT NULL DEFAULT '[]',       -- [{argument, op: equals|in|not_in|prefix, values}]
  description   text NOT NULL DEFAULT '',
  created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CHECK ((subject_type = 'agent') = (subject_id IS NOT NULL)),
  CHECK ((subject_type = 'agent_tag') = (subject_tag IS NOT NULL)),
  CHECK (cardinality(tools) > 0)
);
CREATE INDEX mcp_permissions_server ON mcp_permissions (server_id);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['mcp_servers','mcp_tools','mcp_permissions']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_servers, mcp_tools, mcp_permissions TO nexus_app;

-- Servers whose tools are due for re-discovery (every tenant), for tool drift detection.
CREATE FUNCTION nexus_due_mcp_syncs()
RETURNS TABLE (org_id uuid, server_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM mcp_servers
  WHERE status = 'active' AND (last_synced_at IS NULL OR last_synced_at < now() - interval '6 hours')
$$;
REVOKE ALL ON FUNCTION nexus_due_mcp_syncs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_due_mcp_syncs() TO nexus_app;

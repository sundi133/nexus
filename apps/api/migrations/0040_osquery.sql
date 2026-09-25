-- 0040: osquery on devices: the scheduled inventory pack and live queries (signed agent commands).

-- What the agent's osquery found, one row per device and query of the pack (software, ports…).
CREATE TABLE device_osquery (
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  device_id     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  name          text NOT NULL,
  rows          jsonb NOT NULL DEFAULT '[]'::jsonb,
  truncated     boolean NOT NULL DEFAULT false,
  error         text NOT NULL DEFAULT '',
  collected_at  timestamptz NOT NULL,
  PRIMARY KEY (device_id, name)
);
CREATE INDEX device_osquery_org_name ON device_osquery (org_id, name);

-- NULL: the agent never reported osquery; '': osquery isn't installed; otherwise its version.
ALTER TABLE devices ADD COLUMN osquery_version text, ADD COLUMN osquery_collected_at timestamptz;

-- A live query: one SQL statement sent to many devices as signed commands.
CREATE TABLE live_queries (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  sql           text NOT NULL,
  reason        text NOT NULL DEFAULT '',
  target        jsonb NOT NULL,
  device_count  integer NOT NULL,
  requested_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);
CREATE INDEX live_queries_recent ON live_queries (org_id, created_at DESC);

ALTER TABLE device_commands DROP CONSTRAINT device_commands_action_check;
ALTER TABLE device_commands ADD CONSTRAINT device_commands_action_check CHECK (action IN ('refresh', 'lock', 'restart', 'wipe', 'osquery'));
ALTER TABLE device_commands
  ADD COLUMN args jsonb NOT NULL DEFAULT '{}'::jsonb,   -- signed into the command (e.g. the SQL)
  ADD COLUMN result jsonb,                               -- structured result (rows)
  ADD COLUMN query_id uuid REFERENCES live_queries(id) ON DELETE CASCADE;
CREATE INDEX device_commands_query ON device_commands (query_id) WHERE query_id IS NOT NULL;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['device_osquery','live_queries']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_osquery, live_queries TO nexus_app;

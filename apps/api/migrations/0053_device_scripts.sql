-- 0053: scripts on devices (like JumpCloud Commands). A library of scripts, and runs that send
-- one to chosen devices as signed commands; each device returns its exit code and output.
CREATE TABLE device_scripts (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name        text NOT NULL,
  description text NOT NULL DEFAULT '',
  shell       text NOT NULL CHECK (shell IN ('sh', 'bash', 'zsh', 'powershell')),
  body        text NOT NULL CHECK (length(body) BETWEEN 1 AND 262144),
  created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- What ran: a snapshot of the script (the library can change later), where, and why.
CREATE TABLE script_runs (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  script_id     uuid REFERENCES device_scripts (id) ON DELETE SET NULL,
  name          text NOT NULL,
  shell         text NOT NULL,
  body          text NOT NULL,
  body_sha256   text NOT NULL,
  reason        text NOT NULL,
  target        jsonb NOT NULL,
  device_count  int NOT NULL,
  requested_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);
CREATE INDEX script_runs_recent ON script_runs (org_id, created_at DESC);

ALTER TABLE device_commands DROP CONSTRAINT device_commands_action_check;
ALTER TABLE device_commands ADD CONSTRAINT device_commands_action_check CHECK (action IN ('refresh', 'lock', 'restart', 'wipe', 'osquery', 'script'));
ALTER TABLE device_commands ADD COLUMN script_run_id uuid REFERENCES script_runs (id) ON DELETE CASCADE;
CREATE INDEX device_commands_script_run ON device_commands (script_run_id) WHERE script_run_id IS NOT NULL;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['device_scripts','script_runs']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_scripts, script_runs TO nexus_app;

-- 0010: agent self-update with staged rollouts (SPEC DEV-07).
-- Releases themselves are signed files (not rows): see ADR-017.

CREATE TABLE agent_update_settings (
  org_id               uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  auto_rollout         boolean NOT NULL DEFAULT true,  -- start a rollout when a new release is published
  advance_after_hours  int NOT NULL DEFAULT 24 CHECK (advance_after_hours BETWEEN 0 AND 720), -- 0 = advance by hand only
  updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_rollouts (
  id                uuid PRIMARY KEY,
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  version           text NOT NULL,
  stage             text NOT NULL DEFAULT 'canary' CHECK (stage IN ('canary', 'early', 'all')),
  status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'halted', 'completed', 'cancelled')),
  canary_device_ids uuid[] NOT NULL DEFAULT '{}',
  stage_started_at  timestamptz NOT NULL DEFAULT now(),
  failures_since    timestamptz NOT NULL DEFAULT now(), -- failures before this (e.g. before a resume) don't halt
  halted_reason     text NOT NULL DEFAULT '',
  created_by        uuid REFERENCES users(id) ON DELETE SET NULL, -- null: started automatically
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);
-- At most one unfinished rollout per organization.
CREATE UNIQUE INDEX agent_rollouts_open ON agent_rollouts (org_id) WHERE status IN ('active', 'paused', 'halted');

-- What each device did with each offered version.
CREATE TABLE device_updates (
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  version     text NOT NULL,
  state       text NOT NULL CHECK (state IN ('offered', 'installed', 'failed', 'rolled_back')),
  error       text NOT NULL DEFAULT '',
  from_version text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, version)
);
CREATE INDEX device_updates_version ON device_updates (org_id, version, state);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['agent_update_settings','agent_rollouts','device_updates']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_update_settings, agent_rollouts, device_updates TO nexus_app;

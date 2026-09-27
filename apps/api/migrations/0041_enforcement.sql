-- 0041: device enforcement: block apps (terminate on launch) and domains (hosts-file sinkhole),
-- delivered to agents as a policy signed with the organization's command key.

CREATE TABLE enforcement_rules (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name         text NOT NULL,
  kind         text NOT NULL CHECK (kind IN ('app', 'domain')),
  match        text NOT NULL CHECK (match IN ('name', 'path', 'sha256', 'domain')),
  value        text NOT NULL,
  mode         text NOT NULL DEFAULT 'monitor' CHECK (mode IN ('monitor', 'block')),
  target       jsonb NOT NULL DEFAULT '{"all": true}'::jsonb,   -- {"all": true} or {"group_ids": [...]}
  platforms    text[] NOT NULL DEFAULT '{macos,windows,linux}',
  reason       text NOT NULL DEFAULT '',
  enabled      boolean NOT NULL DEFAULT true,
  created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'app' AND match IN ('name', 'path', 'sha256')) OR (kind = 'domain' AND match = 'domain'))
);
CREATE INDEX enforcement_rules_org ON enforcement_rules (org_id);

-- What agents did (or would have done, in monitor mode). Deduplicated on the device.
CREATE TABLE enforcement_events (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  device_id    uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  rule_id      uuid REFERENCES enforcement_rules(id) ON DELETE SET NULL,
  rule_name    text NOT NULL DEFAULT '',
  action       text NOT NULL CHECK (action IN ('terminated', 'would_terminate', 'domain_blocked', 'failed')),
  subject      text NOT NULL DEFAULT '',   -- the process path or the domain
  user_name    text NOT NULL DEFAULT '',   -- local account that ran it
  count        integer NOT NULL DEFAULT 1,
  detail       text NOT NULL DEFAULT '',
  occurred_at  timestamptz NOT NULL,
  received_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX enforcement_events_recent ON enforcement_events (org_id, occurred_at DESC);
CREATE INDEX enforcement_events_device ON enforcement_events (device_id, occurred_at DESC);

-- What each device last applied (from its check-in).
ALTER TABLE devices ADD COLUMN enforcement_version text NOT NULL DEFAULT '', ADD COLUMN enforcement_status text NOT NULL DEFAULT '';

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['enforcement_rules','enforcement_events']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON enforcement_rules, enforcement_events TO nexus_app;

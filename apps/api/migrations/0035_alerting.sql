-- 0035: low-noise alerting and on-call (SPEC AUD-08, OPS-08, NTF-09, NTF-10). Rules match
-- audit events and fire when a count is reached within a window; an alert stays one alert
-- (deduplicated) while it's open, however many events keep matching; alerts are triaged
-- (acknowledged, assigned, snoozed, resolved with a verdict) and critical ones page on-call
-- through PagerDuty or Opsgenie, with acknowledgements synced both ways.

CREATE TABLE alert_rules (
  id              uuid PRIMARY KEY,
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  builtin_key     text,                               -- the default rule it came from
  name            text NOT NULL,
  description     text NOT NULL DEFAULT '',
  enabled         boolean NOT NULL DEFAULT true,
  severity        text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  match           jsonb NOT NULL,                     -- {types: [...], outcome?, details?: {k: v}}
  group_by        text NOT NULL DEFAULT 'none' CHECK (group_by IN ('none', 'actor', 'target', 'ip')),
  threshold       int NOT NULL DEFAULT 1 CHECK (threshold BETWEEN 1 AND 10000),
  window_minutes  int NOT NULL DEFAULT 5 CHECK (window_minutes BETWEEN 1 AND 1440),
  created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, builtin_key)
);

-- Where each organization's evaluation has got to in the audit log (commit order).
CREATE TABLE alert_cursors (
  org_id       uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  cursor_txid  xid8 NOT NULL,
  cursor_id    uuid NOT NULL
);

-- Matches inside the rules' windows (pruned after a day).
CREATE TABLE alert_hits (
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id    uuid NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
  group_key  text NOT NULL,
  event_id   uuid NOT NULL,
  at         timestamptz NOT NULL,
  PRIMARY KEY (rule_id, event_id)
);
CREATE INDEX alert_hits_window ON alert_hits (rule_id, group_key, at);

CREATE TABLE alerts (
  id               uuid PRIMARY KEY,
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id          uuid REFERENCES alert_rules(id) ON DELETE SET NULL,
  rule_name        text NOT NULL,
  group_key        text NOT NULL,
  subject          text NOT NULL DEFAULT '',          -- who or what it's about, for people
  title            text NOT NULL,
  severity         text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
  count            int NOT NULL DEFAULT 0,
  event_ids        uuid[] NOT NULL DEFAULT '{}',      -- the latest 100
  first_seen_at    timestamptz NOT NULL,
  last_seen_at     timestamptz NOT NULL,
  assignee_id      uuid REFERENCES users(id) ON DELETE SET NULL,
  snoozed_until    timestamptz,
  acknowledged_by  text NOT NULL DEFAULT '',
  acknowledged_at  timestamptz,
  resolved_by      text NOT NULL DEFAULT '',
  resolved_at      timestamptz,
  resolution       text NOT NULL DEFAULT '' CHECK (resolution IN ('', 'true_positive', 'false_positive', 'benign')),
  paged            jsonb NOT NULL DEFAULT '[]',       -- on-call integrations it was sent to
  created_at       timestamptz NOT NULL DEFAULT now()
);
-- One active alert per rule and subject: further matches join it.
CREATE UNIQUE INDEX alerts_active ON alerts (rule_id, group_key) WHERE status <> 'resolved';
CREATE INDEX alerts_org_status ON alerts (org_id, status, last_seen_at DESC);

CREATE TABLE alert_notes (
  id         uuid PRIMARY KEY,
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  alert_id   uuid NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  author_id  uuid REFERENCES users(id) ON DELETE SET NULL,
  author     text NOT NULL,
  body       text NOT NULL,
  at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oncall_integrations (
  id             uuid PRIMARY KEY,
  org_id         uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind           text NOT NULL CHECK (kind IN ('pagerduty', 'opsgenie')),
  name           text NOT NULL,
  secret         bytea NOT NULL,                      -- sealed routing key / API key; AAD oncall:<id>
  region         text NOT NULL DEFAULT 'us' CHECK (region IN ('us', 'eu')),
  min_severity   text NOT NULL DEFAULT 'critical' CHECK (min_severity IN ('low', 'medium', 'high', 'critical')),
  enabled        boolean NOT NULL DEFAULT true,
  inbound_hash   text NOT NULL UNIQUE,                -- sha256 of the webhook token (acknowledgements back)
  last_error     text NOT NULL DEFAULT '',
  last_sent_at   timestamptz,
  created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['alert_rules','alert_cursors','alert_hits','alerts','alert_notes','oncall_integrations']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_rules, alert_cursors, alert_hits, alerts, alert_notes, oncall_integrations TO nexus_app;

-- Organizations with audit events past their alert cursor (every tenant), for evaluation.
-- Organizations never evaluated start from now: there's no point alerting on history.
CREATE FUNCTION nexus_alerts_due()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.org_id FROM alert_cursors c
  WHERE EXISTS (
    SELECT 1 FROM audit_events e
    WHERE e.org_id = c.org_id AND (e.txid, e.id) > (c.cursor_txid, c.cursor_id)
      AND e.txid < pg_snapshot_xmin(pg_current_snapshot()))
  UNION
  SELECT o.id FROM organizations o WHERE NOT EXISTS (SELECT 1 FROM alert_cursors c WHERE c.org_id = o.id)
$$;
REVOKE ALL ON FUNCTION nexus_alerts_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_alerts_due() TO nexus_app;

-- Which organization an inbound on-call webhook belongs to (by its token's hash).
CREATE FUNCTION nexus_oncall_by_token(token_hash text)
RETURNS TABLE (org_id uuid, integration_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM oncall_integrations WHERE inbound_hash = token_hash AND enabled
$$;
REVOKE ALL ON FUNCTION nexus_oncall_by_token(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_oncall_by_token(text) TO nexus_app;

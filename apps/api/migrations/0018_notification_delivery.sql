-- 0018: deliver notifications beyond the inbox: mobile push, email, Slack (SPEC NTF-04/06/07/11).

CREATE TABLE notification_preferences (
  user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email       text NOT NULL DEFAULT 'important' CHECK (email IN ('all', 'important', 'critical')),
  push        text NOT NULL DEFAULT 'important' CHECK (push IN ('all', 'important', 'critical')),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Org-wide alert channel (one message per alert, not per admin).
CREATE TABLE org_alert_channels (
  org_id              uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  slack_webhook       bytea,                      -- sealed incoming-webhook URL
  slack_min_severity  text NOT NULL DEFAULT 'warning' CHECK (slack_min_severity IN ('info', 'warning', 'critical')),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_deliveries (
  id               uuid PRIMARY KEY,
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  notification_id  uuid REFERENCES notifications(id) ON DELETE CASCADE, -- null for org channels (Slack)
  channel          text NOT NULL CHECK (channel IN ('push', 'email', 'slack')),
  status           text NOT NULL CHECK (status IN ('sent', 'failed', 'skipped')),
  detail           text NOT NULL DEFAULT '',
  at               timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notification_deliveries_notification ON notification_deliveries (notification_id);
CREATE INDEX notification_deliveries_org ON notification_deliveries (org_id, at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['notification_preferences','org_alert_channels','notification_deliveries']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_preferences, org_alert_channels, notification_deliveries TO nexus_app;

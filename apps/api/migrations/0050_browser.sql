-- 0050: the Nexus browser extension (AI apps in the browser). An organization token that managed
-- browsers are configured with (not a person's credential: events are self-reported telemetry),
-- the organization's policy for AI web apps and sensitive data, and the events browsers report.
CREATE TABLE browser_tokens (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  name         text NOT NULL,
  token_hash   bytea NOT NULL UNIQUE,
  created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);

CREATE TABLE browser_policies (
  org_id     uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  apps       jsonb NOT NULL DEFAULT '{}',   -- app key -> allow | warn | block
  dlp        jsonb NOT NULL DEFAULT '{}',   -- { detectors: { id: off|monitor|warn|block }, custom: [...] }
  uploads    text NOT NULL DEFAULT 'allow' CHECK (uploads IN ('allow', 'warn', 'block')),
  message    text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE browser_events (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  at          timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  user_email  text NOT NULL DEFAULT '',
  user_id     uuid REFERENCES users (id) ON DELETE SET NULL,
  kind        text NOT NULL CHECK (kind IN ('visit', 'dlp', 'upload')),
  action      text NOT NULL CHECK (action IN ('allowed', 'monitored', 'warned', 'continued', 'blocked')),
  app         text NOT NULL DEFAULT '',
  host        text NOT NULL DEFAULT '',
  detector    text NOT NULL DEFAULT '',
  count       int NOT NULL DEFAULT 1,
  detail      text NOT NULL DEFAULT '',
  extension_version text NOT NULL DEFAULT ''
);
CREATE INDEX browser_events_recent ON browser_events (org_id, at DESC);
CREATE INDEX browser_events_user ON browser_events (user_id);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['browser_tokens','browser_policies','browser_events']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON browser_tokens, browser_policies, browser_events TO nexus_app;

-- Finds the organization for an extension token (and notes its use at most every 5 minutes).
CREATE FUNCTION nexus_browser_token_lookup(p_token_hash bytea)
RETURNS TABLE (org_id uuid, token_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  WITH t AS (
    SELECT id, org_id FROM browser_tokens WHERE token_hash = p_token_hash AND revoked_at IS NULL
  ), touched AS (
    UPDATE browser_tokens b SET last_used_at = now() FROM t
    WHERE b.id = t.id AND (b.last_used_at IS NULL OR b.last_used_at < now() - interval '5 minutes')
  )
  SELECT org_id, id FROM t
$$;
REVOKE ALL ON FUNCTION nexus_browser_token_lookup(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_browser_token_lookup(bytea) TO nexus_app;

-- Browser events are kept 90 days.
CREATE OR REPLACE FUNCTION nexus_apply_retention(p_batch int DEFAULT 10000)
RETURNS TABLE (data text, deleted bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT * FROM (VALUES
    -- Sign-in artifacts: useless once expired; kept a day for troubleshooting.
    ('oidc_codes',              'oidc_codes',              $c$expires_at < now() - interval '1 day'$c$),
    ('auth_challenges',         'auth_challenges',         $c$expires_at < now() - interval '1 day'$c$),
    ('mfa_challenges',          'mfa_challenges',          $c$expires_at < now() - interval '1 day'$c$),
    ('password_resets',         'password_resets',         $c$expires_at < now() - interval '1 day'$c$),
    ('federation_requests',     'federation_requests',     $c$expires_at < now() - interval '1 day'$c$),
    ('device_trust_challenges', 'device_trust_challenges', $c$expires_at < now() - interval '1 day'$c$),
    ('device_pairings',         'device_pairings',         $c$expires_at < now() - interval '1 day'$c$),
    ('agent_assertion_jtis',    'agent_assertion_jtis',    $c$expires_at < now() - interval '1 day'$c$),
    -- Personal data with a natural end: kept 30 days after it, for investigations.
    ('sessions',                'sessions',                $c$coalesce(revoked_at, expires_at) < now() - interval '30 days'$c$),
    ('invitations',             'invitations',             $c$coalesce(accepted_at, revoked_at, expires_at) < now() - interval '30 days'$c$),
    ('notifications',           'notifications',           $c$created_at < now() - interval '180 days'$c$),
    -- Delivery and activity logs.
    ('notification_deliveries', 'notification_deliveries', $c$at < now() - interval '90 days'$c$),
    ('event_deliveries',        'event_deliveries',        $c$at < now() - interval '30 days'$c$),
    ('alert_hits',              'alert_hits',              $c$at < now() - interval '90 days'$c$),
    ('enforcement_events',      'enforcement_events',      $c$occurred_at < now() - interval '90 days'$c$),
    ('device_commands',         'device_commands',         $c$status IN ('done', 'failed', 'expired', 'canceled') AND created_at < now() - interval '90 days'$c$),
    ('live_queries',            'live_queries',            $c$expires_at < now() - interval '30 days'$c$),
    ('browser_events',          'browser_events',          $c$at < now() - interval '90 days'$c$)
  ) AS t(data, tbl, cond)
  LOOP
    data := r.data;
    EXECUTE format('WITH d AS (DELETE FROM %I WHERE ctid IN (SELECT ctid FROM %I WHERE %s LIMIT %s) RETURNING 1) SELECT count(*) FROM d', r.tbl, r.tbl, r.cond, p_batch)
      INTO deleted;
    RETURN NEXT;
  END LOOP;
END
$$;

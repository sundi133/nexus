-- 0065: SaaS discovery and access control. The browser extension counts visits to known SaaS
-- apps (and password sign-ins) per person per day, when the organization turns discovery on.
-- Nothing else about browsing is kept: no addresses, no pages, only the app and the counts.
CREATE TABLE saas_usage (
  org_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  app_key          text NOT NULL,
  user_email       text NOT NULL,
  user_id          uuid REFERENCES users (id) ON DELETE SET NULL,
  day              date NOT NULL,
  visits           int NOT NULL DEFAULT 0,
  password_logins  int NOT NULL DEFAULT 0,
  blocked          int NOT NULL DEFAULT 0,
  last_at          timestamptz NOT NULL,
  PRIMARY KEY (org_id, app_key, user_email, day)
);
CREATE INDEX saas_usage_recent ON saas_usage (org_id, day DESC);
CREATE INDEX saas_usage_user ON saas_usage (user_id);

-- What the organization decided about an app. No row: not reviewed yet.
CREATE TABLE saas_apps (
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  app_key     text NOT NULL,
  status      text NOT NULL CHECK (status IN ('approved', 'unapproved')),
  action      text NOT NULL DEFAULT 'allow' CHECK (action IN ('allow', 'warn', 'block')), -- what browsers do for unapproved apps
  owner_id    uuid REFERENCES users (id) ON DELETE SET NULL,
  notes       text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  updated_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  PRIMARY KEY (org_id, app_key)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['saas_usage','saas_apps']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON saas_usage, saas_apps TO nexus_app;

-- Discovery is off until an admin turns it on.
ALTER TABLE browser_policies ADD COLUMN saas_discovery boolean NOT NULL DEFAULT false;

-- SaaS usage is kept 180 days.
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
    ('browser_events',          'browser_events',          $c$at < now() - interval '90 days'$c$),
    ('saas_usage',              'saas_usage',              $c$day < current_date - 180$c$)
  ) AS t(data, tbl, cond)
  LOOP
    data := r.data;
    EXECUTE format('WITH d AS (DELETE FROM %I WHERE ctid IN (SELECT ctid FROM %I WHERE %s LIMIT %s) RETURNING 1) SELECT count(*) FROM d', r.tbl, r.tbl, r.cond, p_batch)
      INTO deleted;
    RETURN NEXT;
  END LOOP;
END
$$;

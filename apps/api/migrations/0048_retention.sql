-- 0048: retention for data that used to be kept forever. Each rule deletes at most p_batch rows
-- per run (the job runs hourly), so a large backlog never holds long locks. The audit log (per
-- organization setting), process events, jobs and agent nonces have their own pruning.
CREATE FUNCTION nexus_apply_retention(p_batch int DEFAULT 10000)
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
    ('live_queries',            'live_queries',            $c$expires_at < now() - interval '30 days'$c$)
  ) AS t(data, tbl, cond)
  LOOP
    data := r.data;
    EXECUTE format('WITH d AS (DELETE FROM %I WHERE ctid IN (SELECT ctid FROM %I WHERE %s LIMIT %s) RETURNING 1) SELECT count(*) FROM d', r.tbl, r.tbl, r.cond, p_batch)
      INTO deleted;
    RETURN NEXT;
  END LOOP;
END
$$;
REVOKE ALL ON FUNCTION nexus_apply_retention(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_apply_retention(int) TO nexus_app;

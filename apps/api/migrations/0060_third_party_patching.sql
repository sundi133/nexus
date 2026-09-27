-- 0060: third-party app patching (Chrome, Zoom, Slack…, via winget on Windows and a signed-vendor
-- catalog on macOS), next to OS updates; the patch policy can keep them up to date too.
ALTER TABLE devices
  ADD COLUMN third_party_pending int NOT NULL DEFAULT 0,
  ADD COLUMN third_party_since timestamptz;
ALTER TABLE patch_policies ADD COLUMN third_party boolean NOT NULL DEFAULT false;

DROP FUNCTION nexus_patch_due();
CREATE FUNCTION nexus_patch_due()
RETURNS TABLE (org_id uuid, device_id uuid, scope text, restart text, os_due boolean, apps_due boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, device_id, scope, restart, os_due, apps_due FROM (
    SELECT d.org_id, d.id AS device_id, p.scope, p.restart,
      COALESCE(CASE p.scope WHEN 'security' THEN d.security_updates_since ELSE d.updates_pending_since END <= now() - make_interval(days => p.deadline_days), false) AS os_due,
      COALESCE(p.third_party AND d.third_party_since <= now() - make_interval(days => p.deadline_days), false) AS apps_due
    FROM patch_policies p
    JOIN devices d ON d.org_id = p.org_id
    CROSS JOIN LATERAL (SELECT extract(hour FROM now() AT TIME ZONE p.timezone)::int AS h) local
    WHERE p.enabled
      AND d.status = 'active'
      AND d.last_seen_at > now() - interval '10 minutes'
      AND (p.window_start = p.window_end
           OR (p.window_start < p.window_end AND local.h >= p.window_start AND local.h < p.window_end)
           OR (p.window_start > p.window_end AND (local.h >= p.window_start OR local.h < p.window_end)))
      AND NOT EXISTS (
        SELECT 1 FROM device_commands c
        WHERE c.device_id = d.id AND c.action = 'updates'
          AND (c.status IN ('queued', 'sent') OR c.created_at > now() - interval '12 hours'))
  ) due
  WHERE os_due OR apps_due
  LIMIT 1000
$$;
REVOKE ALL ON FUNCTION nexus_patch_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_patch_due() TO nexus_app;

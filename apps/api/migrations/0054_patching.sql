-- 0054: OS patching. The agent reports pending OS updates with its inventory; the server keeps
-- counts (and since when they've been pending) on the device, and a per-org patch policy installs
-- them, as signed 'updates' commands, once they've waited past its deadline, inside its window.
ALTER TABLE device_commands DROP CONSTRAINT device_commands_action_check;
ALTER TABLE device_commands ADD CONSTRAINT device_commands_action_check CHECK (action IN ('refresh', 'lock', 'restart', 'wipe', 'osquery', 'script', 'updates'));

ALTER TABLE devices
  ADD COLUMN updates_checked_at timestamptz,
  ADD COLUMN updates_error text,
  ADD COLUMN updates_pending int NOT NULL DEFAULT 0,
  ADD COLUMN security_updates_pending int NOT NULL DEFAULT 0,
  -- When the device last went from none pending to some: the oldest a pending update can be.
  ADD COLUMN updates_pending_since timestamptz,
  ADD COLUMN security_updates_since timestamptz;

CREATE TABLE patch_policies (
  org_id        uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
  enabled       boolean NOT NULL DEFAULT false,
  scope         text NOT NULL DEFAULT 'security' CHECK (scope IN ('security', 'all')),
  deadline_days int NOT NULL DEFAULT 3 CHECK (deadline_days BETWEEN 0 AND 90),
  restart       text NOT NULL DEFAULT 'never' CHECK (restart IN ('never', 'if_needed')),
  -- Local hours [window_start, window_end) in timezone; wraps past midnight; equal = any time.
  window_start  int NOT NULL DEFAULT 1 CHECK (window_start BETWEEN 0 AND 23),
  window_end    int NOT NULL DEFAULT 5 CHECK (window_end BETWEEN 0 AND 23),
  timezone      text NOT NULL DEFAULT 'UTC',
  updated_by    uuid REFERENCES users (id) ON DELETE SET NULL,
  updated_at    timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE patch_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON patch_policies USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON patch_policies TO nexus_app;

CREATE INDEX device_commands_updates ON device_commands (device_id, created_at DESC) WHERE action = 'updates';

-- Devices (every tenant) whose updates are past their org's deadline, online now, inside the
-- window, and not already being patched (or patched in the last 12 hours, so failures don't loop).
CREATE FUNCTION nexus_patch_due()
RETURNS TABLE (org_id uuid, device_id uuid, scope text, restart text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT d.org_id, d.id, p.scope, p.restart
  FROM patch_policies p
  JOIN devices d ON d.org_id = p.org_id
  CROSS JOIN LATERAL (SELECT extract(hour FROM now() AT TIME ZONE p.timezone)::int AS h) local
  WHERE p.enabled
    AND d.status = 'active'
    AND d.last_seen_at > now() - interval '10 minutes'
    AND CASE p.scope WHEN 'security' THEN d.security_updates_since ELSE d.updates_pending_since END <= now() - make_interval(days => p.deadline_days)
    AND (p.window_start = p.window_end
         OR (p.window_start < p.window_end AND local.h >= p.window_start AND local.h < p.window_end)
         OR (p.window_start > p.window_end AND (local.h >= p.window_start OR local.h < p.window_end)))
    AND NOT EXISTS (
      SELECT 1 FROM device_commands c
      WHERE c.device_id = d.id AND c.action = 'updates'
        AND (c.status IN ('queued', 'sent') OR c.created_at > now() - interval '12 hours'))
  LIMIT 1000
$$;
REVOKE ALL ON FUNCTION nexus_patch_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_patch_due() TO nexus_app;

-- 0043: real-time process events from osquery's event tables (macOS Endpoint Security, Windows ETW,
-- Linux eBPF), with detections. Kept 7 days.

CREATE TABLE device_process_events (
  id                uuid PRIMARY KEY,
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  device_id         uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  time              timestamptz NOT NULL,
  pid               bigint NOT NULL DEFAULT 0,
  path              text NOT NULL DEFAULT '',
  cmdline           text NOT NULL DEFAULT '',   -- capped, secrets redacted
  user_name         text NOT NULL DEFAULT '',
  parent_path       text NOT NULL DEFAULT '',
  ancestors         text[] NOT NULL DEFAULT '{}', -- grandparent and up, nearest first
  responsible_path  text NOT NULL DEFAULT '',   -- macOS: the app responsible for the process
  signer            text NOT NULL DEFAULT '',   -- macOS: team ID or signing ID
  detection         text,                       -- ai_network_tool | ai_shell | exec_from_temp
  severity          text CHECK (severity IN ('info', 'low', 'medium', 'high')),
  received_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_process_events_device ON device_process_events (device_id, time DESC);
CREATE INDEX device_process_events_detections ON device_process_events (org_id, time DESC) WHERE detection IS NOT NULL;

ALTER TABLE device_process_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_process_events USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_process_events TO nexus_app;

-- Retention across every organization (the hourly job has no tenant).
CREATE FUNCTION nexus_prune_process_events(keep interval)
RETURNS bigint
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  WITH d AS (DELETE FROM device_process_events WHERE time < now() - keep RETURNING 1) SELECT count(*) FROM d
$$;
REVOKE ALL ON FUNCTION nexus_prune_process_events(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_prune_process_events(interval) TO nexus_app;

-- What each device's event collector last reported (running, or why not).
ALTER TABLE devices ADD COLUMN events_status text NOT NULL DEFAULT '';

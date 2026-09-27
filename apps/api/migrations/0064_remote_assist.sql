-- 0064: Remote Assist. An admin asks to see a Mac's screen; the person at the Mac approves it; the
-- agent tunnels macOS Screen Sharing (VNC) to a relay in Nexus, and the admin's browser views it.
CREATE TABLE remote_assist_sessions (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  device_id     uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  requested_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  reason        text NOT NULL,
  -- asking: waiting for the person at the Mac; active: approved, viewable; the rest are final.
  status        text NOT NULL DEFAULT 'asking' CHECK (status IN ('asking', 'active', 'declined', 'ended', 'expired', 'failed')),
  detail        text NOT NULL DEFAULT '',     -- who approved, why it failed or ended
  command_id    uuid REFERENCES device_commands (id) ON DELETE SET NULL,
  ticket_hash   text,                         -- the viewer's one-time websocket ticket (SHA-256)
  ticket_expires_at timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  accepted_at   timestamptz,
  ended_at      timestamptz,
  expires_at    timestamptz NOT NULL          -- asking: approval deadline; active: the session's hard end
);
CREATE INDEX remote_assist_device ON remote_assist_sessions (device_id, created_at DESC);
CREATE UNIQUE INDEX remote_assist_one_open ON remote_assist_sessions (device_id) WHERE status IN ('asking', 'active');
CREATE UNIQUE INDEX remote_assist_ticket ON remote_assist_sessions (ticket_hash) WHERE ticket_hash IS NOT NULL;

ALTER TABLE remote_assist_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON remote_assist_sessions USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON remote_assist_sessions TO nexus_app;

-- The viewer's websocket carries only a ticket, so its organization is found from it.
CREATE FUNCTION nexus_remote_assist_ticket(p_hash text)
RETURNS TABLE (session_id uuid, org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id FROM remote_assist_sessions WHERE ticket_hash = p_hash AND ticket_expires_at > now() AND status = 'active'
$$;
REVOKE ALL ON FUNCTION nexus_remote_assist_ticket(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_remote_assist_ticket(text) TO nexus_app;

ALTER TABLE device_commands DROP CONSTRAINT device_commands_action_check;
ALTER TABLE device_commands ADD CONSTRAINT device_commands_action_check CHECK (action IN ('refresh', 'lock', 'restart', 'wipe', 'osquery', 'script', 'updates', 'remote_assist'));

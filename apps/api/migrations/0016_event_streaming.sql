-- 0016: stream audit events to webhooks and SIEMs (SPEC INT-03, AUD-04).
--
-- Ordering without gaps (ADR-021): every audit event records the transaction
-- that wrote it. A reader only takes events from transactions older than the
-- oldest one still running (pg_snapshot_xmin), in (txid, id) order, so an
-- event committed late by a long transaction can never be skipped.

ALTER TABLE audit_events ADD COLUMN txid xid8 NOT NULL DEFAULT pg_current_xact_id();
CREATE INDEX audit_events_stream ON audit_events (org_id, txid, id);

CREATE TABLE event_destinations (
  id                    uuid PRIMARY KEY,
  org_id                uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind                  text NOT NULL CHECK (kind IN ('webhook', 'splunk_hec', 'datadog')),
  name                  text NOT NULL,
  url                   text NOT NULL,
  secret                bytea NOT NULL,             -- sealed: signing secret / HEC token / API key
  config                jsonb NOT NULL DEFAULT '{}', -- e.g. Splunk index, Datadog tags
  format                text NOT NULL DEFAULT 'nexus' CHECK (format IN ('nexus', 'ocsf')),
  event_filter          text[] NOT NULL DEFAULT '{}', -- type prefixes ("user.", "sso.login"); empty = everything
  enabled               boolean NOT NULL DEFAULT true,
  cursor_txid           xid8 NOT NULL,
  cursor_id             uuid NOT NULL,
  consecutive_failures  int NOT NULL DEFAULT 0,
  next_attempt_at       timestamptz NOT NULL DEFAULT now(), -- backoff after failures
  last_error            text NOT NULL DEFAULT '',
  last_delivered_at     timestamptz,
  disabled_reason       text NOT NULL DEFAULT '',
  created_by            uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);

CREATE TABLE event_deliveries (
  id              uuid PRIMARY KEY,
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  destination_id  uuid NOT NULL REFERENCES event_destinations(id) ON DELETE CASCADE,
  at              timestamptz NOT NULL DEFAULT now(),
  ok              boolean NOT NULL,
  http_status     int NOT NULL DEFAULT 0,
  events          int NOT NULL DEFAULT 0,
  duration_ms     int NOT NULL DEFAULT 0,
  error           text NOT NULL DEFAULT ''
);
CREATE INDEX event_deliveries_dest ON event_deliveries (destination_id, at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['event_destinations','event_deliveries']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON event_destinations, event_deliveries TO nexus_app;

-- Which destinations have deliverable events waiting (every tenant; for the worker's tick).
CREATE FUNCTION nexus_destinations_with_backlog()
RETURNS TABLE (org_id uuid, destination_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT d.org_id, d.id FROM event_destinations d
  WHERE d.enabled AND d.next_attempt_at <= now() AND EXISTS (
    SELECT 1 FROM audit_events e
    WHERE e.org_id = d.org_id AND (e.txid, e.id) > (d.cursor_txid, d.cursor_id)
      AND e.txid < pg_snapshot_xmin(pg_current_snapshot()))
$$;
REVOKE ALL ON FUNCTION nexus_destinations_with_backlog() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_destinations_with_backlog() TO nexus_app;

-- 0034: tamper-evident audit log and retention (SPEC AUD-03, AUD-05).
--
-- Events are chained per organization in commit order (txid, id), the same gapless order
-- event streaming uses: h_n = sha256(h_{n-1} || sha256(event)). The chain is sealed into
-- blocks; each block records where it starts and ends, how many events it covers, and the
-- digest before and after. Seals are published as audit events, so the digests also reach
-- the organization's SIEM and archive (an anchor outside Nexus). Retention removes whole
-- sealed blocks only, so what remains always verifies.

CREATE TABLE audit_blocks (
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  seq           bigint NOT NULL,
  from_txid     xid8 NOT NULL,          -- exclusive: the end of the previous block
  from_id       uuid NOT NULL,
  to_txid       xid8 NOT NULL,          -- inclusive
  to_id         uuid NOT NULL,
  count         int NOT NULL,
  first_ts      timestamptz NOT NULL,
  last_ts       timestamptz NOT NULL,
  prev_digest   text NOT NULL,
  digest        text NOT NULL,
  sealed_at     timestamptz NOT NULL DEFAULT now(),
  pruned_at     timestamptz,            -- its events were removed by retention
  PRIMARY KEY (org_id, seq)
);
ALTER TABLE audit_blocks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_blocks USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT ON audit_blocks TO nexus_app;           -- blocks are never changed by the app

-- The audit log can't be edited, even by mistake from a privileged session: only the
-- retention function may delete, and nothing may update.
CREATE FUNCTION nexus_audit_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_setting('nexus.audit_prune', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit events are append-only (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION nexus_audit_immutable();
CREATE TRIGGER audit_blocks_immutable BEFORE UPDATE OF seq, from_txid, from_id, to_txid, to_id, count, prev_digest, digest OR DELETE ON audit_blocks
  FOR EACH ROW EXECUTE FUNCTION nexus_audit_immutable();

-- Organizations with events not yet sealed (every tenant), for the sealing job.
CREATE FUNCTION nexus_audit_unsealed()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id FROM organizations o
  WHERE EXISTS (
    SELECT 1 FROM audit_events e
    WHERE e.org_id = o.id
      AND e.txid < pg_snapshot_xmin(pg_current_snapshot())
      AND (e.txid, e.id) > coalesce(
        (SELECT (b.to_txid, b.to_id) FROM audit_blocks b WHERE b.org_id = o.id ORDER BY b.seq DESC LIMIT 1),
        ('0'::xid8, '00000000-0000-0000-0000-000000000000'::uuid))
  )
$$;
REVOKE ALL ON FUNCTION nexus_audit_unsealed() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_audit_unsealed() TO nexus_app;

-- Retention: removes the events of sealed blocks that are entirely older than the org's
-- retention (default 365 days), and only once every enabled event destination has
-- received them. Returns what it removed per organization.
CREATE FUNCTION nexus_prune_audit(max_blocks int DEFAULT 50)
RETURNS TABLE (org_id uuid, blocks int, events bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  b record;
  n bigint;
BEGIN
  PERFORM set_config('nexus.audit_prune', 'on', true);
  FOR b IN
    SELECT ab.* FROM audit_blocks ab
    JOIN organizations o ON o.id = ab.org_id
    WHERE ab.pruned_at IS NULL
      AND ab.last_ts < now() - make_interval(days => coalesce((o.settings->>'audit_retention_days')::int, 365))
      AND NOT EXISTS (
        SELECT 1 FROM event_destinations d
        WHERE d.org_id = ab.org_id AND d.enabled AND (d.cursor_txid, d.cursor_id) < (ab.to_txid, ab.to_id))
    ORDER BY ab.org_id, ab.seq
    LIMIT max_blocks
  LOOP
    DELETE FROM audit_events e
    WHERE e.org_id = b.org_id AND (e.txid, e.id) > (b.from_txid, b.from_id) AND (e.txid, e.id) <= (b.to_txid, b.to_id);
    GET DIAGNOSTICS n = ROW_COUNT;
    UPDATE audit_blocks SET pruned_at = now() WHERE audit_blocks.org_id = b.org_id AND seq = b.seq;
    org_id := b.org_id; blocks := 1; events := n;
    RETURN NEXT;
  END LOOP;
  PERFORM set_config('nexus.audit_prune', 'off', true);
END $$;
REVOKE ALL ON FUNCTION nexus_prune_audit(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_prune_audit(int) TO nexus_app;

-- Organizations with a sealed chain (every tenant), for the daily verification.
CREATE FUNCTION nexus_audit_chained_orgs()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT DISTINCT org_id FROM audit_blocks
$$;
REVOKE ALL ON FUNCTION nexus_audit_chained_orgs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_audit_chained_orgs() TO nexus_app;

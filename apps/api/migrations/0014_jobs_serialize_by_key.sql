-- 0014: dedupe only among *queued* jobs, and never run two jobs with the same key at once.
-- (0011 also blocked enqueueing while a same-key job was running, which dropped follow-up work
-- that the running job, having read stale state, would not do.)

DROP INDEX jobs_dedupe;
CREATE UNIQUE INDEX jobs_dedupe ON jobs (org_id, dedupe_key) WHERE status = 'queued' AND dedupe_key IS NOT NULL;

CREATE OR REPLACE FUNCTION nexus_claim_jobs(p_limit int, p_lease_seconds int, p_org uuid DEFAULT NULL)
RETURNS SETOF jobs
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  UPDATE jobs SET status = 'running', attempts = attempts + 1,
                  locked_until = now() + make_interval(secs => p_lease_seconds)
  WHERE id IN (
    SELECT j.id FROM jobs j
    WHERE (j.status = 'queued' AND j.run_at <= now() OR j.status = 'running' AND j.locked_until < now())
      AND (p_org IS NULL OR j.org_id = p_org)
      -- Serialize per key: skip while another job with the same key is running (and not expired).
      AND (j.dedupe_key IS NULL OR NOT EXISTS (
        SELECT 1 FROM jobs r
        WHERE r.org_id = j.org_id AND r.dedupe_key = j.dedupe_key AND r.id <> j.id
          AND r.status = 'running' AND r.locked_until >= now()))
    ORDER BY j.run_at
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  )
  RETURNING *
$$;

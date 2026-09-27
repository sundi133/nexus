-- 0011: durable background jobs (directory sync, SCIM provisioning, webhooks, log streaming).
-- Claimed with FOR UPDATE SKIP LOCKED; a crashed worker's lease expires and the job runs again.

CREATE TABLE jobs (
  id           uuid PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  kind         text NOT NULL,
  payload      jsonb NOT NULL DEFAULT '{}',
  status       text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'dead')),
  run_at       timestamptz NOT NULL DEFAULT now(),
  attempts     int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL DEFAULT 8,
  locked_until timestamptz,
  last_error   text NOT NULL DEFAULT '',
  dedupe_key   text,               -- at most one queued/running job per key
  created_at   timestamptz NOT NULL DEFAULT now(),
  finished_at  timestamptz
);
CREATE INDEX jobs_ready ON jobs (run_at) WHERE status IN ('queued', 'running');
CREATE UNIQUE INDEX jobs_dedupe ON jobs (org_id, dedupe_key) WHERE status IN ('queued', 'running') AND dedupe_key IS NOT NULL;
CREATE INDEX jobs_org_kind ON jobs (org_id, kind, created_at DESC);

ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON jobs USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON jobs TO nexus_app;

-- The worker serves every tenant: claim a batch without a tenant context.
CREATE FUNCTION nexus_claim_jobs(p_limit int, p_lease_seconds int, p_org uuid DEFAULT NULL)
RETURNS SETOF jobs
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  UPDATE jobs SET status = 'running', attempts = attempts + 1,
                  locked_until = now() + make_interval(secs => p_lease_seconds)
  WHERE id IN (
    SELECT id FROM jobs
    WHERE (status = 'queued' AND run_at <= now() OR status = 'running' AND locked_until < now())
      AND (p_org IS NULL OR org_id = p_org)
    ORDER BY run_at
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  )
  RETURNING *
$$;

CREATE FUNCTION nexus_finish_job(p_id uuid, p_error text, p_retry_at timestamptz)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  UPDATE jobs SET
    status = CASE WHEN p_error IS NULL THEN 'done' WHEN p_retry_at IS NULL THEN 'dead' ELSE 'queued' END,
    last_error = COALESCE(p_error, ''),
    run_at = COALESCE(p_retry_at, run_at),
    locked_until = NULL,
    finished_at = CASE WHEN p_error IS NULL OR p_retry_at IS NULL THEN now() END
  WHERE id = p_id
$$;

REVOKE ALL ON FUNCTION nexus_claim_jobs(int, int, uuid), nexus_finish_job(uuid, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_claim_jobs(int, int, uuid), nexus_finish_job(uuid, text, timestamptz) TO nexus_app;

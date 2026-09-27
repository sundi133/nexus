-- 0046: periodic work runs on a cluster-wide clock. With several workers, each schedule runs
-- once per interval across all of them (not once per worker), and restarts and deploys don't
-- reset it (an hourly or daily task doesn't rerun on every rollout).
CREATE TABLE schedule_runs (
  name     text PRIMARY KEY,
  last_run timestamptz NOT NULL
);
-- No tenant data. The application reaches it only through nexus_claim_schedule().
ALTER TABLE schedule_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY schedule_runs_none ON schedule_runs USING (false);

-- True for exactly one caller per interval: the one that moved last_run forward.
CREATE FUNCTION nexus_claim_schedule(p_name text, p_every interval)
RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  WITH c AS (
    INSERT INTO schedule_runs (name, last_run) VALUES (p_name, now())
    ON CONFLICT (name) DO UPDATE SET last_run = now()
      WHERE schedule_runs.last_run <= now() - p_every
    RETURNING 1
  )
  SELECT EXISTS (SELECT 1 FROM c)
$$;
REVOKE ALL ON FUNCTION nexus_claim_schedule(text, interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_claim_schedule(text, interval) TO nexus_app;

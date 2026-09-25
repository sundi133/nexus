-- 0021: readiness can confirm the schema is current without reading migration bookkeeping directly.
CREATE FUNCTION nexus_schema_version()
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT max(version) FROM schema_migrations
$$;
REVOKE ALL ON FUNCTION nexus_schema_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_schema_version() TO nexus_app;

-- Queue depth for /metrics (every tenant, counts only).
CREATE FUNCTION nexus_job_queue_stats()
RETURNS TABLE (status text, kind text, n int)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT status, kind, count(*)::int FROM jobs WHERE status IN ('queued', 'running', 'dead') GROUP BY status, kind
$$;
REVOKE ALL ON FUNCTION nexus_job_queue_stats() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_job_queue_stats() TO nexus_app;

-- Retention for finished jobs: done after 7 days, dead after 30 (kept longer for debugging).
CREATE FUNCTION nexus_prune_jobs()
RETURNS int
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  WITH gone AS (
    DELETE FROM jobs
    WHERE (status = 'done' AND finished_at < now() - interval '7 days')
       OR (status = 'dead' AND finished_at < now() - interval '30 days')
    RETURNING 1)
  SELECT count(*)::int FROM gone
$$;
REVOKE ALL ON FUNCTION nexus_prune_jobs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_prune_jobs() TO nexus_app;

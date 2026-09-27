-- 0044: expired agent nonces are pruned by a job, across organizations, instead of on every
-- device request (which cost more than the request itself at fleet scale).
CREATE FUNCTION nexus_prune_agent_nonces()
RETURNS bigint
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  WITH d AS (DELETE FROM agent_nonces WHERE expires_at < now() RETURNING 1) SELECT count(*) FROM d
$$;
REVOKE ALL ON FUNCTION nexus_prune_agent_nonces() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_prune_agent_nonces() TO nexus_app;

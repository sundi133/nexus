-- 0031: dynamic groups (SPEC DIR-05): membership follows a rule on people's attributes.
ALTER TABLE groups
  ADD COLUMN rule               jsonb,          -- null: members are managed by hand (or by a directory)
  ADD COLUMN rule_evaluated_at  timestamptz;

-- Organizations with dynamic groups (every tenant), for the periodic re-evaluation.
CREATE FUNCTION nexus_orgs_with_dynamic_groups()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT DISTINCT org_id FROM groups WHERE rule IS NOT NULL
$$;
REVOKE ALL ON FUNCTION nexus_orgs_with_dynamic_groups() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_orgs_with_dynamic_groups() TO nexus_app;

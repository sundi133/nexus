-- 0039: whether any organization exists yet (for NEXUS_SIGNUP=first, the self-hosted default).
CREATE FUNCTION nexus_any_org() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM organizations)
$$;
REVOKE ALL ON FUNCTION nexus_any_org() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_any_org() TO nexus_app;

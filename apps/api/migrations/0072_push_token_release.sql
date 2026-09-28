-- 0072: a push token identifies one app install. When a phone registers a token that's still on
-- file for another organization (it was paired there before), that old registration is released,
-- which row-level security wouldn't otherwise let the new organization do.
CREATE FUNCTION nexus_release_push_token(p_platform text, p_token text, p_org uuid)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  DELETE FROM push_registrations WHERE platform = p_platform AND token = p_token AND org_id <> p_org
$$;
REVOKE ALL ON FUNCTION nexus_release_push_token(text, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_release_push_token(text, text, uuid) TO nexus_app;

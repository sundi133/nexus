-- 0067: device health alerts. When a device went quiet, or its disk ran low (cleared when it
-- recovers), so each episode is reported once.
ALTER TABLE devices ADD COLUMN offline_since timestamptz;
ALTER TABLE devices ADD COLUMN disk_low_since timestamptz;

-- The scheduler looks for devices that stopped checking in, in every organization.
CREATE FUNCTION nexus_orgs_with_quiet_devices()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT DISTINCT org_id FROM devices WHERE status = 'active' AND offline_since IS NULL AND last_seen_at < now() - interval '1 hour'
$$;
REVOKE ALL ON FUNCTION nexus_orgs_with_quiet_devices() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_orgs_with_quiet_devices() TO nexus_app;

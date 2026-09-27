-- 0045: an enrollment token's uses are the devices it enrolled, counted, not a counter row every
-- enrollment updates: an MDM rollout enrolls thousands of devices with one token at once, and a
-- single hot row serialized them all. (device_enrollment_tokens.uses is no longer maintained.)
CREATE INDEX devices_enrollment_token ON devices (enrollment_token_id);

CREATE OR REPLACE FUNCTION nexus_enrollment_lookup(p_token_hash bytea)
RETURNS TABLE (token_id uuid, org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT t.id, t.org_id FROM device_enrollment_tokens t
  WHERE t.token_hash = p_token_hash AND t.revoked_at IS NULL AND t.expires_at > now()
    AND (t.max_uses IS NULL OR (SELECT count(*) FROM devices d WHERE d.enrollment_token_id = t.id) < t.max_uses)
$$;

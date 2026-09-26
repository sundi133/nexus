-- 0026: device policies in audit or enforce mode, with a grace period (SPEC DPOL-04).
-- Enforced checks decide compliance (and so conditional access); audited ones are only reported.
-- A newly failing enforced check gives the device's user until the grace period ends to fix it.

ALTER TABLE device_policies
  ADD COLUMN mode        text NOT NULL DEFAULT 'enforce' CHECK (mode IN ('audit', 'enforce')),
  ADD COLUMN grace_hours int  NOT NULL DEFAULT 0 CHECK (grace_hours BETWEEN 0 AND 720);

ALTER TABLE device_checks
  ADD COLUMN enforced       boolean NOT NULL DEFAULT true,
  ADD COLUMN failing_since  timestamptz,           -- when this check started failing (kept across re-evaluations)
  ADD COLUMN grace_until    timestamptz;           -- failing, but not counted until then

-- Checks already failing before this upgrade: count from when the device last changed compliance,
-- so switching on a grace period doesn't hand a long-failing device a fresh one.
UPDATE device_checks c SET failing_since = COALESCE(d.compliance_changed_at, c.updated_at)
FROM devices d WHERE d.id = c.device_id AND c.status = 'fail';

ALTER TABLE devices ADD COLUMN compliance_grace_until timestamptz; -- the earliest deadline among checks in grace
CREATE INDEX devices_grace ON devices (compliance_grace_until) WHERE compliance_grace_until IS NOT NULL;

-- Devices whose grace period has run out (every tenant), so they're re-evaluated even if offline.
CREATE FUNCTION nexus_devices_grace_expired()
RETURNS TABLE (org_id uuid, device_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM devices WHERE status = 'active' AND compliance_grace_until IS NOT NULL AND compliance_grace_until <= now() LIMIT 500
$$;
REVOKE ALL ON FUNCTION nexus_devices_grace_expired() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_devices_grace_expired() TO nexus_app;

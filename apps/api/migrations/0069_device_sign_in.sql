-- 0069: sign in with a managed device. A passkey can be bound to the enrolled device it was made
-- on; it then signs its owner in on that device only, together with the agent's attestation.
ALTER TABLE auth_factors ADD COLUMN bound_device_id uuid REFERENCES devices (id) ON DELETE SET NULL;
CREATE INDEX auth_factors_bound_device ON auth_factors (bound_device_id) WHERE bound_device_id IS NOT NULL;

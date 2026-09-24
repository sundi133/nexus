-- 0007: rotation with overlap. A `next` SAML certificate is published in metadata before it
-- signs anything, so service providers can trust it ahead of the switch.
ALTER TABLE signing_keys DROP CONSTRAINT signing_keys_status_check;
ALTER TABLE signing_keys ADD CONSTRAINT signing_keys_status_check CHECK (status IN ('next', 'active', 'retired'));
ALTER TABLE signing_keys ADD COLUMN retired_at timestamptz;

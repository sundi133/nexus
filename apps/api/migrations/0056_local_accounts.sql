-- 0056: laptop sign-in with the company account (like JumpCloud user binding and password sync).
-- People get a local account on devices; their password reaches the device encrypted to the
-- device's own X25519 key (never stored in the clear), whenever Nexus sees it: a sign-in, a
-- change, a reset.
ALTER TABLE devices ADD COLUMN enc_public_key text; -- X25519, base64url, reported in signed check-ins

ALTER TABLE users
  ADD COLUMN local_password_version int NOT NULL DEFAULT 0,
  -- Keyed fingerprint (HMAC with the seal key) of the password last sent to devices: tells a sign-in
  -- with a changed directory password from one with the same password. Set only for people with
  -- local accounts.
  ADD COLUMN local_password_fp text;

CREATE TABLE device_accounts (
  id               uuid PRIMARY KEY,
  org_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  device_id        uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  username         text NOT NULL CHECK (username ~ '^[a-z][a-z0-9._-]{0,19}$'),
  admin            boolean NOT NULL DEFAULT false,
  take_over        boolean NOT NULL DEFAULT false,
  status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'waiting_password', 'active', 'disabled', 'failed')),
  password_version int NOT NULL DEFAULT 0,
  detail           text NOT NULL DEFAULT '',
  reported_at      timestamptz,
  created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (device_id, user_id),
  UNIQUE (device_id, username)
);
CREATE INDEX device_accounts_user ON device_accounts (user_id);

-- A password on its way to a device: only that device can open it. Gone once the device has set it.
CREATE TABLE password_deliveries (
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  version     int NOT NULL,
  ciphertext  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  PRIMARY KEY (device_id, user_id)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['device_accounts','password_deliveries']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_accounts, password_deliveries TO nexus_app;

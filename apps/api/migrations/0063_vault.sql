-- 0063: the password manager, zero-knowledge. Everything secret is encrypted in the browser:
-- items with a per-vault AES key, vault keys wrapped to each member's RSA public key, and each
-- member's private key encrypted with a key derived from their master password. The server
-- stores ciphertext and decides only who may read or write which vault.
CREATE TABLE vault_accounts (
  user_id          uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  org_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  public_key       text NOT NULL,             -- RSA-OAEP SPKI, base64
  private_key_enc  jsonb NOT NULL,            -- {iv, ct}: PKCS#8 encrypted with the master key
  kdf              jsonb NOT NULL,            -- {alg, iterations, salt}
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vaults (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  kind        text NOT NULL CHECK (kind IN ('personal', 'shared')),
  name_enc    jsonb NOT NULL,                 -- {iv, ct} with the vault key
  created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE vault_members (
  vault_id     uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  org_id       uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  wrapped_key  text NOT NULL,                 -- the vault key, RSA-OAEP-wrapped to this member
  role         text NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
  added_by     uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (vault_id, user_id)
);
CREATE INDEX vault_members_user ON vault_members (user_id);

CREATE TABLE vault_items (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  vault_id    uuid NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
  data        jsonb NOT NULL,                 -- {iv, ct} with the vault key
  created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  updated_by  uuid REFERENCES users (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vault_items_vault ON vault_items (vault_id);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['vault_accounts','vaults','vault_members','vault_items']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON vault_accounts, vaults, vault_members, vault_items TO nexus_app;

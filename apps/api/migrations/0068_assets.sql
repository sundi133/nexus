-- 0068: asset management. Hardware the organization owns, enrolled or not: who has it, where it
-- is, what it cost and when its warranty ends, with a history of who had it when.
CREATE TABLE assets (
  id                   uuid PRIMARY KEY,
  org_id               uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  tag                  text NOT NULL,             -- the asset tag on the sticker
  name                 text NOT NULL DEFAULT '',
  kind                 text NOT NULL DEFAULT 'other' CHECK (kind IN ('laptop', 'desktop', 'phone', 'tablet', 'monitor', 'peripheral', 'network', 'server', 'other')),
  make                 text NOT NULL DEFAULT '',
  model                text NOT NULL DEFAULT '',
  serial               text NOT NULL DEFAULT '',
  status               text NOT NULL DEFAULT 'in_stock' CHECK (status IN ('in_stock', 'assigned', 'in_repair', 'retired', 'lost')),
  assigned_to          uuid REFERENCES users (id) ON DELETE SET NULL,
  location             text NOT NULL DEFAULT '',
  vendor               text NOT NULL DEFAULT '',
  purchase_date        date,
  purchase_cost_cents  bigint CHECK (purchase_cost_cents >= 0),
  currency             text NOT NULL DEFAULT 'USD' CHECK (currency ~ '^[A-Z]{3}$'),
  warranty_until       date,
  notes                text NOT NULL DEFAULT '',
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, tag)
);
CREATE INDEX assets_serial ON assets (org_id, serial) WHERE serial <> '';
CREATE INDEX assets_assignee ON assets (assigned_to);

CREATE TABLE asset_events (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  asset_id    uuid NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
  at          timestamptz NOT NULL DEFAULT now(),
  kind        text NOT NULL CHECK (kind IN ('created', 'checked_out', 'checked_in', 'updated')),
  user_id     uuid REFERENCES users (id) ON DELETE SET NULL,   -- who got it, or who returned it
  status      text NOT NULL DEFAULT '',
  note        text NOT NULL DEFAULT '',
  actor_id    uuid REFERENCES users (id) ON DELETE SET NULL
);
CREATE INDEX asset_events_asset ON asset_events (asset_id, at DESC);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['assets','asset_events']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON assets, asset_events TO nexus_app;

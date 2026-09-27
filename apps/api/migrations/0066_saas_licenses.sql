-- 0066: SaaS licenses. What the organization pays for each app (seats, price, renewal) and who
-- holds the seats: the people assigned to the app in Nexus single sign-on, or a list.
CREATE TABLE saas_licenses (
  id               uuid PRIMARY KEY,
  org_id           uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  app_key          text NOT NULL,
  plan             text NOT NULL DEFAULT '',
  seats            int NOT NULL CHECK (seats >= 0),
  unit_cost_cents  bigint NOT NULL DEFAULT 0 CHECK (unit_cost_cents >= 0), -- per seat per billing period
  currency         text NOT NULL DEFAULT 'USD' CHECK (currency ~ '^[A-Z]{3}$'),
  billing          text NOT NULL DEFAULT 'annual' CHECK (billing IN ('monthly', 'annual')),
  renews_on        date,
  seat_source      text NOT NULL DEFAULT 'sso' CHECK (seat_source IN ('sso', 'list')),
  owner_id         uuid REFERENCES users (id) ON DELETE SET NULL,
  notes            text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX saas_licenses_org ON saas_licenses (org_id, app_key);

-- Seat holders, for licenses whose seats come from a list.
CREATE TABLE saas_license_holders (
  license_id  uuid NOT NULL REFERENCES saas_licenses (id) ON DELETE CASCADE,
  org_id      uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  email       text NOT NULL,
  added_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (license_id, email)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['saas_licenses','saas_license_holders']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON saas_licenses, saas_license_holders TO nexus_app;

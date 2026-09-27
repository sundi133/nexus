-- 0030: access reviews / certification campaigns (SPEC JIT-05). A review snapshots who has an
-- app, a group or an admin role; reviewers keep or revoke each; closing applies the result.

CREATE TABLE access_reviews (
  id               uuid PRIMARY KEY,
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name             text NOT NULL,
  scope_type       text NOT NULL CHECK (scope_type IN ('app', 'group', 'admin_roles')),
  scope_id         uuid,                               -- the app or group
  reviewer_kind    text NOT NULL CHECK (reviewer_kind IN ('users', 'manager')),
  reviewer_ids     uuid[] NOT NULL DEFAULT '{}',       -- the reviewers, or (manager) who reviews people without one
  on_no_decision   text NOT NULL DEFAULT 'keep' CHECK (on_no_decision IN ('keep', 'revoke')),
  status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
  due_at           timestamptz NOT NULL,
  reminded_at      timestamptz,
  closed_at        timestamptz,
  summary          jsonb NOT NULL DEFAULT '{}',
  created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE access_review_items (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  review_id     uuid NOT NULL REFERENCES access_reviews(id) ON DELETE CASCADE,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  grant_kind    text NOT NULL CHECK (grant_kind IN ('app_user', 'group_member', 'role')),
  grant_ref     text NOT NULL,                        -- app id, group id (for "via group" too) or role
  via           text NOT NULL DEFAULT '',             -- "via group Finance", for context
  reviewer_id   uuid REFERENCES users(id) ON DELETE SET NULL,
  decision      text CHECK (decision IN ('keep', 'revoke')),
  note          text NOT NULL DEFAULT '',
  decided_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  decided_at    timestamptz,
  outcome       text NOT NULL DEFAULT '' CHECK (outcome IN ('', 'kept', 'revoked', 'already_gone', 'skipped')),
  UNIQUE (review_id, user_id, grant_kind, grant_ref)
);
CREATE INDEX access_review_items_reviewer ON access_review_items (reviewer_id) WHERE decision IS NULL;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['access_reviews','access_review_items']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON access_reviews, access_review_items TO nexus_app;

-- Reviews due for a reminder (a day before) or for closing (every tenant).
CREATE FUNCTION nexus_access_reviews_due()
RETURNS TABLE (org_id uuid, review_id uuid, action text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id, CASE WHEN due_at <= now() THEN 'close' ELSE 'remind' END FROM access_reviews
  WHERE status = 'open' AND (due_at <= now() OR (reminded_at IS NULL AND due_at <= now() + interval '1 day'))
  LIMIT 200
$$;
REVOKE ALL ON FUNCTION nexus_access_reviews_due() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_access_reviews_due() TO nexus_app;

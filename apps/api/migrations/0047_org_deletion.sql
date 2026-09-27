-- 0047: an organization can be deleted, with every tenant row, after a grace period any owner can
-- cancel. What's kept afterwards is a deletion certificate outside the tenant (no tenant data
-- beyond the name and row counts), for the customer's and the operator's records.
ALTER TABLE organizations
  ADD COLUMN deletion_scheduled_for timestamptz,
  ADD COLUMN deletion_requested_by uuid,
  ADD COLUMN deletion_requested_at timestamptz,
  ADD COLUMN deletion_reason text;

CREATE TABLE deleted_organizations (
  organization_id    uuid PRIMARY KEY,
  name               text NOT NULL,
  slug               text NOT NULL,
  requested_by_email text,
  requested_at       timestamptz,
  reason             text,
  deleted_at         timestamptz NOT NULL DEFAULT now(),
  row_counts         jsonb NOT NULL
);
-- Operators read it as the owner role; the application reaches it only through the function below.
ALTER TABLE deleted_organizations ENABLE ROW LEVEL SECURITY;
CREATE POLICY deleted_organizations_none ON deleted_organizations USING (false);

CREATE FUNCTION nexus_orgs_due_for_deletion()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id FROM organizations WHERE deletion_scheduled_for <= now() ORDER BY deletion_scheduled_for
$$;

-- Deletes a due organization and everything in it (every tenant table cascades from
-- organizations), including its append-only audit log. Returns the certificate plus who to tell,
-- or NULL if it isn't due (cancelled meanwhile, or already gone).
CREATE FUNCTION nexus_delete_organization(p_org uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  o organizations%ROWTYPE;
  t text;
  n bigint;
  counts jsonb := '{}';
  notify text[];
  requester text;
BEGIN
  SELECT * INTO o FROM organizations WHERE id = p_org AND deletion_scheduled_for <= now() FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  FOR t IN
    SELECT c.relname FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace
    WHERE ns.nspname = 'public' AND c.relkind = 'r'
      AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'org_id' AND NOT a.attisdropped)
    ORDER BY 1
  LOOP
    EXECUTE format('SELECT count(*) FROM %I WHERE org_id = $1', t) INTO n USING p_org;
    IF n > 0 THEN counts := counts || jsonb_build_object(t, n); END IF;
  END LOOP;
  SELECT email INTO requester FROM users WHERE id = o.deletion_requested_by;
  SELECT array_agg(DISTINCT u.email) INTO notify FROM user_roles r JOIN users u ON u.id = r.user_id
    WHERE r.org_id = p_org AND r.role = 'owner' AND u.status = 'active';
  PERFORM set_config('nexus.audit_prune', 'on', true);   -- the audit log goes with the organization
  DELETE FROM organizations WHERE id = p_org;
  PERFORM set_config('nexus.audit_prune', 'off', true);
  INSERT INTO deleted_organizations (organization_id, name, slug, requested_by_email, requested_at, reason, row_counts)
    VALUES (o.id, o.name, o.slug, requester, o.deletion_requested_at, o.deletion_reason, counts);
  RETURN jsonb_build_object(
    'organization_id', o.id, 'name', o.name, 'deleted_at', now(), 'requested_at', o.deletion_requested_at,
    'row_counts', counts,
    'notify', to_jsonb(ARRAY(SELECT DISTINCT e FROM unnest(coalesce(notify, '{}') || requester) e WHERE e IS NOT NULL ORDER BY 1)));
END
$$;
REVOKE ALL ON FUNCTION nexus_orgs_due_for_deletion() FROM PUBLIC;
REVOKE ALL ON FUNCTION nexus_delete_organization(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_orgs_due_for_deletion() TO nexus_app;
GRANT EXECUTE ON FUNCTION nexus_delete_organization(uuid) TO nexus_app;

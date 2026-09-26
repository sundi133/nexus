-- 0042: people's risk scores (the access graph's summary), kept to notice when someone's risk rises.

CREATE TABLE risk_scores (
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  score        integer NOT NULL,
  level        text NOT NULL CHECK (level IN ('low', 'medium', 'high', 'critical')),
  factors      jsonb NOT NULL DEFAULT '[]'::jsonb,
  computed_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id)
);
CREATE INDEX risk_scores_org ON risk_scores (org_id, score DESC);

ALTER TABLE risk_scores ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON risk_scores USING (org_id = nexus_current_org()) WITH CHECK (org_id = nexus_current_org());
GRANT SELECT, INSERT, UPDATE, DELETE ON risk_scores TO nexus_app;

-- Organizations with active devices or AI agents: the hourly risk job's work list.
CREATE FUNCTION nexus_orgs_for_risk()
RETURNS TABLE (org_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM devices WHERE status = 'active'
  UNION
  SELECT org_id FROM ai_agents
$$;
REVOKE ALL ON FUNCTION nexus_orgs_for_risk() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION nexus_orgs_for_risk() TO nexus_app;

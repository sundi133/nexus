-- 0032: AI agent identities (SPEC AGT-01/02/03/06/07). Agents are workloads with an
-- owner, their own credentials and short-lived, audience-bound tokens; they can be
-- stopped at once (kill switch).

CREATE TABLE ai_agents (
  id                  uuid PRIMARY KEY,
  org_id              uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                text NOT NULL,
  description         text NOT NULL DEFAULT '',
  owner_user_id       uuid REFERENCES users(id) ON DELETE SET NULL,
  owner_group_id      uuid REFERENCES groups(id) ON DELETE SET NULL,
  environment         text NOT NULL DEFAULT 'production' CHECK (environment IN ('production', 'staging', 'development')),
  runtime             text NOT NULL DEFAULT '',     -- e.g. LangGraph, Claude Agent SDK, n8n
  model               text NOT NULL DEFAULT '',     -- e.g. claude-sonnet-5
  risk_tier           text NOT NULL DEFAULT 'medium' CHECK (risk_tier IN ('low', 'medium', 'high', 'critical')),
  tags                text[] NOT NULL DEFAULT '{}',
  client_id           text NOT NULL UNIQUE,         -- agt_…, used at the token endpoint
  status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  status_reason       text NOT NULL DEFAULT '',
  token_ttl_minutes   int NOT NULL DEFAULT 15 CHECK (token_ttl_minutes BETWEEN 5 AND 60),
  -- Kill switch: tokens issued before this are refused everywhere.
  tokens_valid_after  timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z',
  last_token_at       timestamptz,
  last_seen_at        timestamptz,                  -- last token or gateway call
  created_by          uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);
CREATE INDEX ai_agents_owner ON ai_agents (owner_user_id) WHERE owner_user_id IS NOT NULL;

-- How an agent proves itself: a client secret, a public key (private_key_jwt), or a token
-- from a workload identity provider (GitHub Actions, AWS, GCP, Kubernetes…).
CREATE TABLE agent_credentials (
  id            uuid PRIMARY KEY,
  org_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  agent_id      uuid NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
  kind          text NOT NULL CHECK (kind IN ('secret', 'public_key', 'federated')),
  name          text NOT NULL DEFAULT '',
  secret_hash   text,
  hint          text NOT NULL DEFAULT '',
  public_jwk    jsonb,
  key_id        text,
  fed_issuer    text,
  fed_subject   text,
  fed_audience  text,
  expires_at    timestamptz,
  last_used_at  timestamptz,
  created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz,
  CHECK ((kind = 'secret') = (secret_hash IS NOT NULL)),
  CHECK ((kind = 'public_key') = (public_jwk IS NOT NULL)),
  CHECK ((kind = 'federated') = (fed_issuer IS NOT NULL AND fed_subject IS NOT NULL AND fed_audience IS NOT NULL))
);
CREATE INDEX agent_credentials_agent ON agent_credentials (agent_id) WHERE revoked_at IS NULL;

-- private_key_jwt assertions are single-use.
CREATE TABLE agent_assertion_jtis (
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  jti         text NOT NULL,
  expires_at  timestamptz NOT NULL,
  PRIMARY KEY (org_id, jti)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['ai_agents','agent_credentials','agent_assertion_jtis']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = nexus_current_org()) '
                   'WITH CHECK (org_id = nexus_current_org())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON ai_agents, agent_credentials, agent_assertion_jtis TO nexus_app;

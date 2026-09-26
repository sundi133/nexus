-- 0038: rate limits shared by every API replica (login, MFA, API keys, MCP gateway, ...).
-- Counters in a fixed window; unlogged (a crash just resets them) and swept periodically.
-- Keys are namespaced by limiter and aren't tenant data, so no row-level security.
CREATE UNLOGGED TABLE rate_limits (
  key       text PRIMARY KEY,
  reset_at  timestamptz NOT NULL,
  count     int NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limits TO nexus_app;

# nexus: the Votal Nexus CLI

Config as code for Votal Nexus: keep policies in Git, review a plan in pull requests, and promote from staging to production. It also covers the few things you need during an incident.

## Install and sign in

```bash
pnpm --filter @nexus/cli build        # produces dist/nexus.mjs (single file, Node 22+)
export NEXUS_URL=https://api.nexus.example.com
export NEXUS_TOKEN=nxk_…              # an API key with org:manage and the scopes for what you change
```

Or run `nexus login --url … --token …`, which saves the credentials to `~/.config/nexus/credentials.json` (mode 0600). Environment variables take precedence.

## Config as code

```bash
nexus config export -o nexus.yaml      # current settings, by name, no secrets
nexus config plan  -f nexus.yaml       # what would change (read-only)
nexus config apply -f nexus.yaml       # asks for confirmation; --yes in CI
nexus config apply -f nexus.yaml --prune   # also delete what listed sections don't mention
```

The document covers these sections:
- `settings`
- `groups` (except directory-managed ones; memberships follow people and dynamic-group rules)
- `conditional_access`
- `device_policies`
- `alert_rules`
- `agents` (no credentials)
- `mcp_servers` with their tool `permissions`

How it applies:
- Everything is referred to by name (apps, groups, people by email, agents, MCP servers by slug), so one file works across environments.
- Sections you leave out are untouched.
- Apply is all or nothing. It carries the plan's ID, so it refuses if anything changed since the plan.
- Every change is in the audit log, marked `via: config`.

**Secrets:** MCP server tokens are never exported. Name an environment variable instead, and the CLI fills it in on apply:

```yaml
mcp_servers:
  - slug: github
    name: GitHub
    url: https://api.githubcopilot.com/mcp/
    auth: { kind: bearer, token_env: NEXUS_MCP_GITHUB_TOKEN }
    permissions:
      - { effect: allow, subject: "tag:support", tools: ["*"], risks: [read] }
```

## Incident basics

```bash
nexus agents list
nexus agents suspend "Support triage bot" --reason "prompt injection, INC-42"
nexus alerts list --status active
nexus audit verify                      # exit code 2 if the audit log was tampered with
```

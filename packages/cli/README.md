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

## On-prem Active Directory / LDAP connector

When Nexus can't reach your domain controllers (hosted Nexus, no inbound firewall rules), run the connector inside your network. It reads AD or LDAP read-only and reconciles Nexus through a SCIM connection, the same way Okta or Entra ID provision:
- it creates and updates people;
- it deactivates people who are disabled or removed in the directory (a burst of deactivations pauses for an admin's approval);
- it syncs groups, with nested membership expanded.

1. In Nexus, go to **Directory sync → Set up SCIM** and copy the SCIM URL and token.
2. Write `connector.yaml`:

```yaml
scim:
  url: https://api.nexus.example.com/scim/v2
  token_env: NEXUS_SCIM_TOKEN
ldap:
  preset: active_directory            # or openldap, custom
  url: ldaps://dc1.corp.example.com:636
  ca_cert_file: /etc/nexus/corp-ca.pem   # if your DCs use an internal CA
  bind_dn: CN=svc-nexus,OU=Service Accounts,DC=corp,DC=example,DC=com
  bind_password_env: LDAP_BIND_PASSWORD
  base_dn: DC=corp,DC=example,DC=com
  # user_base_dn, group_base_dn, user_search_filter, group_search_filter, disabled_filter: optional
groups: true
```

3. Run it on a schedule, for example every 15 minutes from a systemd timer, cron or a container:

```bash
NEXUS_SCIM_TOKEN=… LDAP_BIND_PASSWORD=… nexus directory push -c connector.yaml --dry-run   # see first
NEXUS_SCIM_TOKEN=… LDAP_BIND_PASSWORD=… nexus directory push -c connector.yaml
```

The service account's password never leaves your network, and no inbound ports are needed. If Nexus *can* reach the directory (self-hosted, or LDAPS published), connect it directly under **Directory sync → Connect a directory → Active Directory / LDAP** instead. That also lets people sign in with their directory password.

## Incident basics

```bash
nexus agents list
nexus agents suspend "Support triage bot" --reason "prompt injection, INC-42"
nexus alerts list --status active
nexus audit verify                      # exit code 2 if the audit log was tampered with
```

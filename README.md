# Votal Nexus

**Identity, device and AI-agent security on one platform.**

Nexus is a cloud control plane for three kinds of actor: **humans** (users, SSO, MFA, SCIM), **devices** (a Windows/macOS/Linux agent, posture, policies, commands) and **AI agents** (agent identities, an MCP Gateway, and guardrails). All three are governed by one policy engine and one audit trail.

One public `/v1` API serves the **web console**, the **Nexus Mobile** app (authenticator + responder), the CLI and Terraform.

## Quick start

Requires Node 22+, pnpm and Docker.

```bash
pnpm install
cp .env.example .env
pnpm db:up                           # Postgres on :55432, Mailpit (email inbox) on http://localhost:58025
pnpm --filter @nexus/api dev         # API on :8080 (migrates on start)
pnpm --filter @nexus/web dev         # Console on http://localhost:3100
```

Open http://localhost:3100/signup and create an organization.

| Command | What it does |
|---|---|
| `pnpm --filter @nexus/api test` | End-to-end API tests against the `nexus_test` database |
| `pnpm api:spec` | Regenerate `apps/api/openapi.json` and the typed client in `packages/api-client` |
| `pnpm typecheck` | Typecheck every package |
| `pnpm db:reset` | Drop and recreate the local database |

## Repository layout

```
apps/api              TypeScript API (Hono + zod-openapi, Kysely, Postgres RLS). SQL migrations in migrations/
apps/web              Next.js console + BFF (holds the session in an HttpOnly cookie; proxies /bff/v1/* → API)
apps/mobile           Nexus Mobile (Expo): authenticator + responder; see apps/mobile/README.md
packages/api-client   Typed client generated from the OpenAPI spec, shared by web and mobile
deploy/compose        Local Postgres + Mailpit
docs/                 Spec, architecture, UI and roadmap
```

## Documentation

| Doc | What's in it |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | Product spec: goals, personas, requirements (with IDs), NFRs, SecOps / notifications / mobile, release exit criteria |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, one API for web + mobile + CLI, notifications pipeline, policy engine, tokens, data model, security, decision log |
| [docs/UI.md](docs/UI.md) | UX principles, SecOps experience, key screens, mobile app, design system |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Release A (top 30%) → B (30–80%) → C; epics, owners, how we build, progress |

## Status

Release A1 in progress. Built:

- **Identity:** tenancy with Postgres RLS, sign-up, password + TOTP (replay-safe), **passkeys and passwordless sign-in**, **push MFA via Nexus Mobile** (number matching, signed approvals, "This wasn't me" alerts), sessions, inline step-up
- **Policy:** org MFA requirement with forced enrollment, **secure baseline** with impact preview, change history
- **SSO:** OpenID Connect provider (code flow + PKCE, discovery, JWKS, userinfo) and SAML 2.0 IdP (SP- and IdP-initiated, signed assertions, metadata import) per organization, applications with user/group assignments, and an app launcher
- **Directory:** users and groups, **email invitations**, **CSV import with preview**, lifecycle actions (suspend, contain, reset MFA), admin roles
- **Visibility:** audit log, notification inbox with live updates, Overview with a "Needs attention" queue

Next up: app catalog and certificate rotation, then the device agent.

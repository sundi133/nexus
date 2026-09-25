# Votal Nexus — Delivery Roadmap

| | |
|---|---|
| **Status** | Draft v0.2 |
| **Date** | 2026-09-24 |
| **Planning start** | 2026-10-05 |
| **Related** | [SPEC.md](SPEC.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [UI.md](UI.md) |

---

## 1. Strategy in one page

| Release | Coverage | When | What a customer gets | Business outcome |
|---|---|---|---|---|
| **Foundations** | walking skeleton | wk 1–4 | Nothing to sell; proves every layer end-to-end | Team velocity |
| **A** | **0 → 30%**, the most important features | mo 1–5 | Workforce identity (SSO + passkey/push MFA + directory sync), **device trust** for macOS/Windows, **agent identities + MCP gateway v1**, a **mobile authenticator and responder app**, notifications, audit + SIEM | 3–5 design partners in production |
| **B** | **30 → 80%** | mo 6–11 | Full lifecycle (SCIM, offboarding, JIT), device enforcement and commands, Linux, full AI security (drift, guardrails, OBO, self-hosted gateway), SecOps workflows (alert triage, cases, access graph), Terraform | GA, SOC 2 Type I, paid expansion |
| **C** | 80% + | mo 12+ | LDAP, RADIUS, patch management, app deployment, SaaS discovery, macOS MDM, MSP | Enterprise breadth |

**How we chose the first 30%:** a feature is in Release A if a SecOps buyer would **refuse a pilot without it** (SSO, MFA, directory sync, audit/SIEM), or if it is **the reason to pick Nexus** (device trust on every login, agent identity, contain from your phone). Everything else waits, no matter how "standard" it looks on a competitor's pricing page.

## 2. How we build (applies to every epic)

1. **Vertical slices, not layers.** Every feature ships through all layers at once: OpenAPI (zod) → API handler → permission → audit event → notification category (if any) → web UI → mobile (if in scope) → docs. We never build "the backend for SSO" in one quarter and "the UI" in the next.
2. **API first, then clients.** The OpenAPI change is reviewed first (it is the contract for web, mobile, CLI and customers). Generated clients then unblock frontend and mobile work in parallel with the backend.
3. **Definition of done** for any feature:
   - [ ] OpenAPI documented, with examples
   - [ ] Permission in the Cedar catalog; denied paths tested
   - [ ] Audit event(s) emitted and visible in the explorer
   - [ ] Report-only / preview mode, if it is a policy
   - [ ] "Why?" explanation, if it makes an access decision
   - [ ] Web UI with empty, loading and error states; keyboard accessible
   - [ ] Mobile screen, if listed in SPEC §5.23 for this release
   - [ ] Playwright E2E happy path; RLS test for new tables
   - [ ] Public docs page and changelog entry
4. **Dogfood from week 4.** Votal runs its own company login on Nexus as soon as the walking skeleton works.
5. **Design partners get a Slack Connect channel** and a build every 2 weeks.

## 3. Team (9 people)

| Role | Code | Focus |
|---|---|---|
| Tech lead / architect | **TL** | Identity architecture, policy engine, security model, code review |
| Backend engineer | **BE1** | Directory, authn, IdP (OIDC/SAML), SCIM |
| Backend engineer | **BE2** | Platform, audit, notifications, API, integrations |
| Device engineer | **DE1** | Agent core, macOS + Linux, enrollment, device CA, device trust |
| Device engineer | **DE2** | Windows, posture, policies, commands |
| Frontend engineer | **FE** | Design system, admin console, portal |
| Mobile / frontend engineer | **MOB** | Expo app, native key modules, push; helps FE on the console |
| Security / AI engineer | **AI** | Agent identity, MCP Gateway, guardrails integration |
| QA / SRE / security | **SRE** | CI/CD, infrastructure, load tests, E2E, pentest, SOC 2 |

The mobile engineer is hired **before month 1**. Push MFA and the responder app are in Release A, and the mobile engineer also relieves the frontend bottleneck.

**Capacity:** 9 × 4.3 wk/mo × 80% focus ≈ **31 eng-weeks per month**.

## 4. Timeline

```
Month:         0     1     2     3     4     5     6     7     8     9    10    11    12
Foundations  ████
Release A          [ A1: identity ][ A2: SSO + device trust ][ A3: agents + responder ]
Release B                                                     [ lifecycle · devices · AI security · SecOps ]
Release C                                                                                      [ ... ]
Milestones   ▲ skeleton        ▲ dogfood SSO          ▲ pilot (A)                 ▲ GA (B)
```

## 5. Foundations: walking skeleton (weeks 1–4)

**The one flow that proves the architecture:** a user signs in to the web console with a passkey → the mobile app gets a **push approval** → they approve with Face ID → the sign-in appears in the **audit log** and in the **notification inbox on both web and mobile**, in real time.

| Epic | Scope | Owner | Eng-wks |
|---|---|---|---|
| F.1 Monorepo & tooling ✅ | pnpm + Turborepo, TypeScript, Hono + zod-openapi, Kysely, SQL migrations, compose deps, launch configs | TL, SRE | 3 |
| F.2 CI/CD & environments | GitHub Actions, preview env per PR, staging, Terraform (EKS, RDS, ElastiCache, NATS via Helm, ClickHouse Cloud), Argo CD, EAS builds for mobile | SRE | 4 |
| F.3 Platform core ✅ (partial) | Tenancy + RLS ✅, error model ✅, cursor pagination ✅, audit-in-transaction ✅, background jobs ✅ (ADR-018); still to do: OTel | TL, BE2 | 5 |
| F.4 Auth skeleton ✅ | Org sign-up ✅, password + TOTP (replay-safe) ✅, passkeys + passwordless ✅, sessions ✅, BFF cookie ✅, step-up with inline UI ✅ | BE1 | 4 |
| F.5 Audit + notify skeleton ✅ (partial) | Audit in Postgres ✅, inbox ✅, SSE via LISTEN/NOTIFY ✅, push/email/Slack delivery ✅, audit streaming ✅; still to do: ClickHouse | BE2 | 4 |
| F.6 Web design system v0 ✅ (partial) | Tokens ✅, AppShell ✅, ⌘K ✅, inbox drawer ✅, tables/forms/dialogs ✅; still to do: Storybook | FE | 4 |
| F.7 Mobile shell ✅ (partial) | Expo app ✅, QR pairing ✅, Ed25519 device key ✅, push-MFA approval with number matching ✅, inbox ✅, push-token registration ✅, APNs/FCM senders ✅; still to do: hardware-backed key, DPoP | MOB | 4 |
| F.8 Agent spike | Go agent skeleton, gRPC stream, osquery embedded on macOS + Windows | DE1, DE2 | 6 |
| F.9 MCP spike | Pass-through MCP proxy with JWT verification + Cedar eval | AI | 3 |
| | | **Total** | **37** |

## 6. Release A: the most important 30% (months 1–5)

### A1: Identity you can sign in with (months 1–2)

| Epic | Requirements | Owner | Eng-wks |
|---|---|---|---|
| Directory + sync | DIR-01..04, DIR-08 (Google Workspace, Entra), ORG-01/02/04 | BE1 | 6 |
| MFA & sessions | AUTH-01..08, MOB-02 (push MFA + TOTP) | BE1, MOB | 7 |
| Admin RBAC v1 | RBAC-01, 04, 06 | TL | 3 |
| Notifications v1 | NTF-01..04, 06 (email, Slack), 07, 08, 11 | BE2 | 5 |
| SecOps basics | OPS-01 secure baseline, OPS-02 needs attention, OPS-06 change history, OPS-10 setup wizard | BE2, FE | 4 |
| Console | Overview, Users, Groups, Settings (auth, notifications), onboarding checklist | FE | 6 |
| Mobile | MOB-01, 03, 09, 10; Codes tab | MOB | 3 |
| | | **Subtotal** | **34** |

**Progress (2026-09-24):** ✅ MFA policy + forced enrollment (ORG-04, AUTH-07) · ✅ secure baseline with impact preview (OPS-01) · ✅ settings change history (OPS-06) · ✅ email invitations · ✅ CSV import with dry-run (DIR-03) · ✅ passkeys (AUTH-03/05) · ✅ push MFA + Nexus Mobile (AUTH-04, MOB-01/02/03) · ✅ OIDC SSO: provider, apps, assignments, app launcher (SSO-01, SSO-05, PORT-01) · ✅ SAML 2.0 IdP: SP- and IdP-initiated, signed assertions, metadata, SP metadata import (SSO-02, SSO-04) · ✅ app catalog with 10 templates + per-app SAML attribute mapping (SSO-03, SSO-06) · ✅ key/certificate rotation with overlap + expiry warning (SSO-07). **SSO for Release A is complete.** · ✅ Device agent (Go, macOS/Windows/Linux) with signed check-ins, enrollment tokens, inventory + posture, 5 device policies in audit mode, My devices (DEV-02..06, DPOL-01..03, PORT-03). · ✅ Conditional access with device trust: policies (require MFA / managed device / compliant device / block) scoped by app, group and user with exclusions, report-only → enforce with 7-day impact, what-if simulator, per-decision explanations in the audit log; browser sessions proven to be on a device via the agent's loopback attestation (origin-bound, single-use, 12 h); device check and MFA step-up during SSO for OIDC and SAML (CA-01..05, OPS-04, OPS-05). · ✅ Agent self-update: Ed25519-signed releases verified by the agent, staged rollouts (canary → 10% → all) that widen on their own and halt on the first failure, self-test before swap, on-device rollback of crash-looping or unhealthy versions, an Agent updates console (DEV-07). · ✅ Service install (launchd, systemd, Windows service) and a universal macOS `.pkg` with MDM enrollment config, plus codesign/notarization hooks (DEV-01, macOS). · ✅ Windows `.msi` (x64 and arm64): silent install with SERVER/TOKEN for Intune and GPO, service registration, a locked-down state folder, in-place upgrades, and an install/upgrade/uninstall test on Windows in CI. Still to do: real Apple Developer ID and Windows code-signing certificates (hooks in place). · ✅ Background job queue in Postgres (F.3 jobs). · ✅ Directory sync from Google Workspace and Microsoft Entra ID: test-before-save, group scoping, dry-run preview, create/adopt/update/suspend/reactivate, group mirroring, invitations, scheduled runs, and a mass-deprovisioning guard with an approval flow (DIR-08). · ✅ SCIM 2.0 provisioning to apps: create/adopt, update on change, deactivate or delete, group push, per-account dashboard with retry, failure alerts, 6-hourly reconcile, SSRF-guarded endpoints (SCIM-01/02). · ✅ One-click offboarding, now or scheduled for a last day: deprovision, sign out, remove roles, groups, assignments and factors, unassign devices, deactivate provisioned accounts (DIR-06, DIR-02 scheduled deactivation). · ✅ Scoped, expiring API keys that act as themselves (INT-02). · ✅ Webhooks (HMAC-signed) and SIEM streaming to Splunk HEC and Datadog, Nexus JSON or OCSF 1.3, filtered, ordered and gapless, with backfill, delivery log, backoff and failure alerts (INT-03, AUD-04). · ✅ Audit archives to Amazon S3, Google Cloud Storage and S3-compatible storage (SigV4, gzipped JSON lines in date partitions, idempotent retries, Object Lock–ready) and streaming to Microsoft Sentinel via the Logs Ingestion API (AUD-04). · ✅ Account recovery: one-time recovery codes, "can't use any MFA method" admin help, self-service password reset that never bypasses MFA, password change, breached-password checks via HIBP k-anonymity everywhere a password is set (AUTH-01/02/08, PORT-02). · ✅ Notification delivery: APNs (HTTP/2, token auth) and FCM v1 push, content-free, with dead-token pruning; email; org alerts to Slack once per alert; per-user preferences with critical always delivered; delivery log per notification; retries without duplicates; quiet hours and a daily email digest in the user's time zone (DST-safe), with one summary per channel when they end and critical alerts never held (NTF-04/06/07/11). · ✅ Admin safety: verified email domains with cross-org exclusivity and daily re-checks (ORG-02); owners confirm admin actions with a passkey (RBAC-04, in the secure baseline); break-glass accounts with sealed emergency passwords, lockout exemptions and alerts on every use (RBAC-05); one-click undo of settings changes (OPS-06). · ✅ Production readiness: startup config checks, /healthz and /readyz, Prometheus metrics, JSON request logs, API/worker roles with graceful shutdown, security headers and CSP, seal-key rotation with `reseal`, container images, production compose with automatic HTTPS, smoke test, restore-tested backups, load test, CI with security guards and dependency audit, [operations](OPERATIONS.md) and [security](SECURITY.md) docs. **The enterprise-approval track (directory sync, SCIM, offboarding, API keys, SIEM, recovery, notifications, admin safety, production readiness) is complete.** · ✅ Sign in through the organization's own IdP (AUTH-10): OIDC (Okta, Entra ID, Google, Auth0, Ping) and SAML 2.0 (ADFS, Entra ID, Okta…), home-realm discovery by verified domain, JIT accounts and linking by IdP subject, IdP MFA trusted only when reported (configurable), test sign-ins that show the claims, and "require the IdP" for a domain (break-glass excepted, only after a successful test). · ✅ Inbound SCIM 2.0 (DIR-07): Okta, Entra ID, JumpCloud and others push users and groups (create, update, deactivate, delete, group membership) with filters and PATCH as each vendor sends them; break-glass accounts invisible; reactivation only undoes suspensions SCIM made; deprovisioning setting honoured; a burst of deactivations is paused (429) until an admin approves; token shown once, rotatable. Also fixed: PATCH endpoints reset unmentioned fields to defaults (Zod 4 `.partial()` keeps defaults) for users, groups and directory connections. · ✅ Device policies in enforce or audit mode with grace periods (DPOL-04): audited checks are reported only; an enforced failure counts after its grace period (measured from the first failure, re-checked even for offline devices), and the device's user is told what to fix and by when. · ✅ MDM signals from Microsoft Intune and Jamf Pro: devices matched by serial number (at once for new enrollments), a "managed and compliant in your MDM" policy, the MDM's view on each device, and a coverage list of MDM devices without the Nexus agent. · ✅ Device actions (DEV-09): refresh, lock, restart through the agent with commands signed by a per-organization Ed25519 key the agent pins at enrollment (CMD-03; checked for device, expiry and replay, results reported back, CMD-04), and lock / restart / wipe through Intune or Jamf (Jamf lock returns a one-time unlock PIN); wipe needs the hostname typed, step-up, a reason and its own permission. · ✅ Linux `.deb`/`.rpm` (amd64, arm64) with systemd, enroll.conf or `install` enrollment, keep-key-on-remove, purge; install-tested in CI (DEV-01 Linux). · ✅ Access requests (JIT-01/02/04) and just-in-time admin (OPS-11): a catalog of requestable apps, groups and admin roles (never owner), approval chains of up to five stages (manager, group, specific people, a role) with fallback to admins, pre-approved eligible people who activate with MFA and a reason, automatic expiry, early give-back and revocation, and an audit trail linking request, approvals, grant and end; managers settable by admins and SCIM. · ✅ Access reviews (JIT-05): campaigns over an app (direct and via-group access), a group or admin roles, reviewed by managers (with fallbacks) or chosen reviewers, bulk keep/revoke, closing by hand or at the due date with a reminder the day before, undecided default, never the last owner or a break-glass account, request-granted access ended through its request, CSV evidence export. · ✅ Dynamic groups (DIR-05): a rule builder (all/any of email, domain, department, title, name, manager, directory source) with a live preview of who matches and what would change; members follow the rule within a minute of people changing (and a 15-minute sweep), flow to provisioned apps like manual changes, and can't be edited by hand; directory-managed and requestable groups can't have rules, and access reviews leave dynamic membership to the rule. · ✅ AI agent identities (AGT-01/02/03/06/07). Registry with owner, environment, runtime, model, risk tier and tags. Credentials are client secrets, private_key_jwt, or workload identity federation (GitHub Actions, GitLab, Kubernetes, GCP). Tokens are 15-minute and gateway-bound via `client_credentials`. The kill switch invalidates tokens at once. Offboarding or containing an owner suspends their agents until they are reassigned. Stale agents are flagged. Each agent has an activity timeline. · ✅ MCP gateway (MCP-01/02/03/04/07/08/10). Upstream servers use streamable HTTP with sealed credentials. Tools are discovered and approved by hash, with drift detection every 6 hours that shows what changed. Risk classes come from annotations and heuristics, and admins can override them. Rules are per-tool allow/deny for an agent, a tag or every agent, with risk and argument conditions, and a what-if simulator shows decisions. Also: per-agent rate limits, RFC 9728 protected resource metadata, and a trace of every call and refusal. Console pages cover Agents and MCP servers. · ✅ Tamper-evident audit and retention (AUD-03, AUD-05). The audit log is a per-tenant hash chain sealed hourly, with digests anchored in your SIEM or archive. Verification runs daily and on demand, with a critical alert on failure. The database enforces append-only, and retention (30 days to 10 years) never loses undelivered events or breaks the chain. Next, the 80% track: alerting and on-call, reports, config as code, RBAC v2, on-prem AD/LDAP.

> Before GA: validate each catalog template against the vendor's current docs and a real tenant, and run the OpenID conformance suite.

**Milestone:** Votal employees use Nexus for daily login with push MFA.

### A2: SSO and device trust (months 2–4)

| Epic | Requirements | Owner | Eng-wks |
|---|---|---|---|
| OIDC provider + SAML IdP + 10 catalog apps | SSO-01..05, 07 | BE1 | 8 |
| Enrollment, device CA, packaging (macOS + Windows) | DEV-01, 02, 06 | DE1, SRE | 8 |
| Inventory, posture, compliance (audit-only) | DEV-03..05, DPOL-01..03 | DE2 | 8 |
| Agent self-update ✅ | DEV-07 | DE1 | 3 |
| Conditional access + device trust ✅ | CA-01..05, OPS-04 "Why?", OPS-05 report-only → enforce | TL, DE1 | 7 |
| Console + portal | Apps, Devices, Device detail, CA builder + what-if, Portal (PORT-01..03), block page with fix steps | FE, MOB | 8 |
| | | **Subtotal** | **42** |

**Milestone:** SSO into Slack/Google/GitHub/AWS is blocked from a laptop with FileVault off, and the user sees how to fix it.

### A3: Agents, MCP and the responder (months 4–5)

| Epic | Requirements | Owner | Eng-wks |
|---|---|---|---|
| Agent identities v1 | AGT-01..03, 06 (registry, federation, kill switch) | AI | 5 |
| MCP Gateway v1 (hosted, streamable HTTP) | MCP-01, 03, 04, 08 | AI, TL | 6 |
| Contain playbook | OPS-03 (user, device, agent) | BE2 | 3 |
| Mobile responder | MOB-04, 05 | MOB | 5 |
| Audit explorer + SIEM + webhooks + public API | AUD-01, 02, 04; INT-01..03 | BE2 | 6 |
| Console | Agents, MCP servers & tool permissions, Audit explorer | FE | 6 |
| Hardening | Pentest #1, load test of auth paths, SLO dashboards, runbooks | SRE | 4 |
| | | **Subtotal** | **35** |

**Release A total: ~111 eng-weeks** against ~155 of capacity (5 months), leaving **~30% buffer** for bugs, design-partner requests and signing-certificate delays.

**Release A exit:** the scenario in [SPEC §7](SPEC.md#7-release-exit-criteria) passes as an automated E2E test and live with 3–5 design partners.

## 7. Release B: from 30% to 80% (months 6–11)

Release B runs as **five parallel tracks**, each with a lead, so the team does not serialize.

| Track | Epics (requirements) | Owners | Eng-wks |
|---|---|---|---|
| **Lifecycle** | SCIM in/out (SCIM-01..04, DIR-07) · one-click offboarding (DIR-06, AGT-07) · dynamic groups, branding, federated login, risk signals (DIR-05, ORG-03, AUTH-09, 10) · RBAC v2 + JIT admin (RBAC-02, 03, 05, OPS-11) · access requests + reviews with Slack/mobile approvals (JIT-01..05, INT-04, MOB-06) · 30+ catalog apps, claim mapping (SSO-03, 06) | BE1, TL | 28 |
| **Devices** | Linux agent (DEV-01) · enforcement + 20+ templates + custom policies (DPOL-01, 04, 05) · commands, scripts, device actions, tamper protection (CMD-01..05, DEV-08, 09) · live query (DEV-10) · software inventory + CVEs (SW-01) | DE1, DE2 | 22 |
| **AI security** | Tool drift, virtual servers, rate limits, risk classes, stdio, self-hosted gateway (MCP-02, 05, 07, 09, 10) · on-behalf-of delegation + consent + chains (AGT-04, 05, 10) · guardrails (GRD-01..05, MCP-06) · agent observability + AI tool discovery (AGT-08, 09, SAAS-03) | AI, TL | 23 |
| **SecOps** | Low-noise alerting + triage + on-call (OPS-08, AUD-08, NTF-09, 10, MOB-07) · investigation cases (OPS-09) · access graph (AUD-07) · retention, tamper-evidence, reports (AUD-03, 05, 06) · Terraform + CLI + YAML (OPS-07, INT-05) · web push + Teams (NTF-05, 06) · end-user mobile (MOB-08, PORT-04, 05) | BE2, MOB | 26 |
| **Console & quality** | Console screens for all tracks · load/chaos tests (50k agent connections, 2k MCP calls/s) · pentest #2 · SOC 2 Type I | FE, SRE | 22 |
| | | **Total** | **~121** |

That is ~121 eng-weeks against ~186 of capacity (6 months). The larger buffer (~35%) is deliberate: Release B runs alongside supporting production customers.

**Release B exit:** GA; latency NFRs met; SOC 2 Type I; offboarding revokes 100% of access in < 60 s.

## 8. Release C: the long tail (month 12+)

Cloud LDAP (LEG-01) · Cloud RADIUS (LEG-02) · patch management (SW-02) · app deployment (SW-03) · SaaS discovery (SAAS-01, 02) · basic macOS MDM (LEG-03) · MSP multi-org (ORG-05) · LLM API proxy (MCP-11) · SOC 2 Type II. Prioritize by paying-customer demand.

## 9. Risks and mitigations

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Windows agent reliability | Release A slip | High | osquery for collection; device lab from week 1; macOS pilots first if needed |
| Apple / Google push or app-store review delays | Push MFA slip | Medium | TestFlight / internal track from week 4; TOTP fallback always available |
| Signing certificates (Apple Developer ID, Windows EV) | Blocks agent + app release | Medium | **Start procurement in week 1** |
| SAML vendor quirks | Catalog slip | High | Top 10 apps chosen by design partners; SAML test harness |
| Push MFA fatigue attacks | Security incident | Medium | Number matching, rate limits, "Deny, this wasn't me" raises an alert; passkeys preferred |
| MCP spec churn | Gateway rework | Medium | Thin protocol adapter; conformance tests |
| Scope creep toward JumpCloud parity | Diluted differentiation | High | SPEC §2.2 non-goals are binding; new asks go to Release C unless a design partner blocks on them |

## 10. Getting started: the first two weeks

**Week 1**
1. Lock the decisions in ARCHITECTURE §17 (ADR-001..012) and answer SPEC §9 questions 1–3.
2. Start procurement: Apple Developer Program (org), Windows EV code-signing certificate, Google Play console, domains (`nexus.votal.ai`), AWS accounts (US + EU), APNs key, Firebase project.
3. Scaffold the monorepo (F.1): `apps/web`, `apps/mobile`, `cmd/api`, `packages/{api-client,core,tokens,ui}`, `api/openapi/nexus.yaml`, `db/migrations`, `deploy/compose`.
4. Write the first OpenAPI slice: `/v1/me`, `/v1/me/notifications`, `/v1/me/stream`, `/v1/me/push-registrations`, `/v1/mfa/challenges/{id}:approve`, `/v1/audit/events`.
5. Set up the device lab (Macs + Windows PCs, ARM + x86) and 2 test phones (iOS + Android).

**Week 2**
1. Stand up `make dev`: Postgres, Redis, NATS and ClickHouse in compose, with Tilt running `api`, `worker`, `web` and `mobile` (Expo dev client).
2. Tenancy + RLS + outbox merged, with the RLS test harness in CI.
3. Web: AppShell, sign-in page, inbox drawer on the design-system tokens.
4. Mobile: PKCE login against staging, push registration, a push that arrives on a real device.
5. Recruit design partners: target 5 conversations and 3 signed pilot LOIs by the end of month 1.

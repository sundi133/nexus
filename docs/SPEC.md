# Votal Nexus — Product Specification

| | |
|---|---|
| **Status** | Draft v0.2 |
| **Date** | 2026-09-24 |
| **Owner** | Product / Tech Lead |
| **Related** | [ARCHITECTURE.md](ARCHITECTURE.md) · [UI.md](UI.md) · [ROADMAP.md](ROADMAP.md) |

---

## 1. Summary

**Votal Nexus** is a cloud control plane that manages the identity and access of three kinds of actor on one policy engine:

1. **Humans**: employees, contractors, admins
2. **Devices**: Windows, macOS and Linux endpoints
3. **Agents**: AI agents, MCP clients, service and workload identities

It covers the core of a cloud directory: users, groups, SSO, MFA, SCIM, device inventory and policy, remote commands, and audit. What sets it apart is **first-class agent identity, MCP tool authorization and AI guardrails**, all evaluated against the same device-trust and identity signals.

> **Positioning:** *"Know who (or what) is acting, from which device, on whose behalf, and stop it when it shouldn't."*

We are **not** building a feature-for-feature JumpCloud clone. We target the ~80% of commercially important functionality and spend the saved effort on the agent and MCP layer.

## 2. Goals and non-goals

### 2.1 Goals (first 12 months)

| # | Goal | Measure |
|---|------|---------|
| G1 | A mid-market company (50–2,000 employees) can run its workforce identity on Nexus | Users, groups, MFA, SSO to ≥ 20 catalog apps, SCIM to ≥ 10 apps |
| G2 | Admins can see and control every managed device | Agent on Win/macOS/Linux; inventory, posture, policies and commands |
| G3 | Access decisions use device trust | Conditional access that blocks SSO from non-compliant devices |
| G4 | AI agents are first-class, governed identities | Agent registry, owners, scoped credentials, on-behalf-of delegation, kill switch |
| G5 | Every MCP tool call is authenticated, authorized, inspected and logged | MCP Gateway with per-tool policy and guardrails; overhead p95 < 15 ms |
| G6 | Everything is auditable | 100% of mutations and auth decisions land in the audit log; SIEM export |
| G7 | The UI is best-in-class | Admin tasks in ≤ 3 clicks; command palette; SUS score ≥ 80 in usability tests |

### 2.2 Non-goals (v1)

- Full MDM catalog (Apple DEP/ABM deep profiles, iOS/Android). Only a **basic macOS MDM** comes in Release C. (The Nexus **mobile app** is an authenticator and responder app, not MDM.)
- LDAP and RADIUS servers. Deferred to Release C.
- Asset management (procurement, depreciation) and remote desktop.
- Replacing an HRIS. We **consume** HRIS data through SCIM and connectors.
- On-prem control plane. The control plane is SaaS only; the **MCP Gateway** and **agent** can run in the customer's environment.

## 3. Personas

| Persona | Needs | Primary surface |
|---|---|---|
| **IT Admin (Priya)** | Onboard and offboard people fast, keep devices compliant, fewer tickets | Admin console |
| **SecOps / Security Engineer (Marcus)** | Enforce MFA and device trust, get paged on real issues only, contain incidents in seconds (including from a phone), export to SIEM, manage config as code | Admin console, **mobile app**, Slack, SIEM, API/Terraform |
| **AI Platform Engineer (Lena)** | Register agents, connect MCP servers, give agents least-privilege tool access | Admin console (AI section), CLI, API |
| **Employee (Sam)** | One login, app launcher, request access, enroll MFA and device, approve sign-ins with a tap | User portal, **mobile app**, desktop agent tray |
| **Auditor (Grace)** | Read-only evidence: who had access to what, and when | Reports, read-only role |
| **MSP Operator** (later) | Manage many tenants | Multi-tenant console (Release C) |

## 4. Domain model (glossary)

| Concept | Definition |
|---|---|
| **Organization (Tenant)** | Isolation boundary. Owns all other objects. Has a region (US/EU). |
| **Principal** | Anything that can authenticate. Subtypes: `User`, `ServiceIdentity`, `AgentIdentity`, `Device`. |
| **User** | Human principal. Status: `staged → active → suspended → deprovisioned`. |
| **Group** | Static or **dynamic** (rule-based, e.g. `department == "Eng" && country == "US"`) set of users and/or devices. |
| **ServiceIdentity** | Non-human, non-AI workload (CI job, backend service). Uses client credentials or workload identity federation. |
| **AgentIdentity** | An AI agent. Has an **owner** (a user or team), a **purpose**, a **model/runtime**, allowed **tools**, and an optional **on-behalf-of** delegation mode. |
| **Device** | Enrolled endpoint with a device certificate, inventory, posture and an assigned user. |
| **Application** | An SSO/SCIM target (SAML or OIDC relying party). |
| **MCP Server** | A registered upstream MCP endpoint whose **tools**, **resources** and **prompts** are discovered and cataloged. |
| **Tool** | One MCP tool (e.g. `github.create_pull_request`), with a risk level and data classification. |
| **Policy** | A Cedar policy (see [ARCHITECTURE §6](ARCHITECTURE.md#6-policy-engine)): `permit`/`forbid` over principal, action, resource and context. |
| **Device Policy** | A desired-state configuration for a device (e.g. disk encryption on, screen lock ≤ 5 min). Different from an *access* policy. |
| **Command** | A signed script or action queued for one or more devices, with results. |
| **Access Request** | A time-bound request for a role, group, app or tool, routed to approvers. |
| **Session** | An authenticated session (browser SSO, agent token, or MCP session). Can be revoked. |
| **Event** | An immutable audit record (CloudEvents format). |

## 5. Functional requirements

Requirement IDs are stable and referenced from epics and tests. **Priority:** P0 = required for the release exit, P1 = should have, P2 = nice to have.

**Release** (see [ROADMAP.md](ROADMAP.md)):
- **A** is the most important ~30%, enough for a pilot a SecOps team would actually run.
- **B** takes coverage from ~30% to ~80% and makes the product enterprise-ready and differentiated.
- **C** holds the long tail (80%+).

### 5.1 Tenancy and administration (`ORG`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| ORG-01 | Self-serve sign-up creates an organization, an owner admin and a region choice | P0 | A |
| ORG-02 | Custom domain verification (DNS TXT); verified domains drive user matching and SSO discovery | P0 | A |
| ORG-03 | Branding: logo, colors and login page text for the user portal and login screens | P1 | B |
| ORG-04 | Org settings: session lifetime, password policy, allowed MFA factors, IP allowlists | P0 | A |
| ORG-05 | Multi-org management for MSPs (parent/child orgs) | P2 | C |

### 5.2 Directory: users and groups (`DIR`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| DIR-01 | CRUD users with a standard schema (name, email, username, title, department, manager, employee ID, location) plus **custom attributes** (typed) | P0 | A |
| DIR-02 | User lifecycle: `staged → active → suspended → deprovisioned`, with scheduled activation and deactivation dates | P0 | A |
| DIR-03 | Bulk import (CSV) with dry-run preview and per-row errors | P0 | A |
| DIR-04 | Static groups for users and devices; nested groups are **not** supported in v1 | P0 | A |
| DIR-05 | Dynamic groups using an attribute rule builder, with a live preview of members | P1 | B |
| DIR-06 | Offboarding workflow in one action: suspend, revoke sessions, remove from groups, deprovision apps via SCIM, lock devices, transfer agent ownership | P0 | B |
| DIR-07 | Inbound provisioning from an HRIS (SCIM 2.0 server endpoint; Workday/BambooHR/Rippling connectors later) | P1 | B |
| DIR-08 | Import from Google Workspace and Microsoft Entra ID (one-time and continuous sync) | P0 | A |

### 5.3 Authentication (`AUTH`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| AUTH-01 | Password login with Argon2id hashing, breached-password check (k-anonymity HIBP) and configurable policy | P0 | A |
| AUTH-02 | TOTP MFA (RFC 6238) with recovery codes | P0 | A |
| AUTH-03 | WebAuthn / passkeys, both platform and roaming authenticators | P0 | A |
| AUTH-04 | Push MFA through the **Nexus mobile app** (and later the desktop tray), with number matching and a device-bound key (see MOB-02) | P0 | A |
| AUTH-05 | Passwordless login (passkey-first) as an org option | P0 | A |
| AUTH-06 | Session management: list and revoke sessions per user; admins can revoke any | P0 | A |
| AUTH-07 | Step-up authentication for sensitive actions (admin role changes, agent credential issue) | P0 | A |
| AUTH-08 | Self-service password reset and MFA re-enrollment with admin approval | P0 | A |
| AUTH-09 | Login risk signals: new device, impossible travel, TOR/VPN ASN, recorded on the session | P1 | B |
| AUTH-10 | Federated login from an external IdP (Google, Entra) into Nexus | P1 | B |

### 5.4 Admin RBAC (`RBAC`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| RBAC-01 | Built-in roles: Owner, Admin, Help Desk, Device Manager, Security Analyst, AI Admin, Read-only/Auditor, Billing | P0 | A |
| RBAC-02 | Custom roles from a permission catalog (`users:read`, `devices:command`, `agents:credentials:issue`, …) | P1 | B |
| RBAC-03 | Scoped roles: a role limited to a set of groups (e.g. Help Desk for "EMEA" only) | P1 | B |
| RBAC-04 | Admin actions require MFA; the Owner role requires a passkey | P0 | A |
| RBAC-05 | Break-glass account with sealed credentials and loud alerting on use | P1 | B |
| RBAC-06 | Every permission check is enforced server-side via the policy engine; the UI hides disallowed actions | P0 | A |

### 5.5 Devices and endpoint agent (`DEV`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| DEV-01 | Signed, notarized agent installers: `.pkg` (macOS, universal), `.msi` (Windows x64/arm64), `.deb`/`.rpm` (Linux x64/arm64) | P0 | A (macOS, Windows) · B (Linux) |
| DEV-02 | Enrollment through an org enrollment token (MDM-deployable) or user-initiated login; the device gets an X.509 identity via CSR, with the key in the TPM / Secure Enclave where available | P0 | A |
| DEV-03 | Heartbeat every 60 s over a persistent mTLS stream; last-seen and online state in the UI | P0 | A |
| DEV-04 | Inventory: hardware, OS and version, serial, disks, network interfaces, local users, installed software, running services | P0 | A |
| DEV-05 | Posture signals: disk encryption (FileVault/BitLocker/LUKS), firewall, screen lock, OS up to date, EDR present, SIP/Secure Boot, admin users | P0 | A |
| DEV-06 | Device ↔ user association (primary user), used by conditional access and the portal | P0 | A |
| DEV-07 | Agent self-update with staged rollout rings (canary → 10% → 100%) and automatic rollback | P0 | A |
| DEV-08 | Tamper resistance: the agent runs as a system service, uninstall requires an org token, and tamper attempts emit events | P1 | B |
| DEV-09 | Device actions: lock, restart, shutdown, wipe (macOS/Windows), with confirmation and audit | P1 | B |
| DEV-10 | Live query: run a read-only osquery SQL query on a set of devices and stream results | P1 | B |

### 5.6 Device policies (`DPOL`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| DPOL-01 | Policy templates per OS: disk encryption, screen lock, password complexity, firewall, auto-update, USB storage block, Gatekeeper/SmartScreen | P0 | A (5, audit-only) · B (20+) |
| DPOL-02 | Assign policies to device groups; conflict resolution by priority, shown in the UI | P0 | A |
| DPOL-03 | Per-device compliance status for each policy (`compliant`, `non_compliant`, `pending`, `error`) with reason | P0 | A |
| DPOL-04 | Enforce mode vs. audit-only mode per policy | P0 | B |
| DPOL-05 | Custom policies from a signed script with a check and remediation pair | P1 | B |

### 5.7 Commands and scripts (`CMD`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| CMD-01 | Script library (bash, zsh, PowerShell, Python) with versions | P0 | B |
| CMD-02 | Run a script on devices or groups, now or on a schedule, or triggered by an event (e.g. on enrollment) | P0 | B |
| CMD-03 | Every command payload is **signed by the control plane**; the agent verifies it before execution | P0 | B |
| CMD-04 | Streamed stdout/stderr, exit code and duration per device; timeouts; cancellation | P0 | B |
| CMD-05 | Two-person approval for commands targeting > N devices or marked high-risk | P1 | B |

### 5.8 SSO and application catalog (`SSO`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| SSO-01 | Nexus acts as an **OIDC provider** (auth code + PKCE, refresh, client credentials, device code); discovery and JWKS | P0 | A |
| SSO-02 | Nexus acts as a **SAML 2.0 IdP** (SP- and IdP-initiated, signed assertions, attribute mapping) | P0 | A |
| SSO-03 | App catalog with pre-built templates (Google Workspace, Microsoft 365, Slack, GitHub, AWS IAM Identity Center, Atlassian, Salesforce, Zoom, Notion, Figma, …) | P0 | A (10 apps) · B (30+) |
| SSO-04 | Custom SAML/OIDC apps with metadata import | P0 | A |
| SSO-05 | App assignment to users and groups; the user portal shows assigned apps | P0 | A |
| SSO-06 | Per-app attribute and claim mapping using expressions | P1 | B |
| SSO-07 | Certificate rotation with overlap windows and expiry alerts | P0 | A |

### 5.9 SCIM provisioning (`SCIM`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| SCIM-01 | Outbound SCIM 2.0 client: create, update and deactivate users and push groups to apps | P0 | B |
| SCIM-02 | Per-app provisioning dashboard: last sync, errors, retry | P0 | B |
| SCIM-03 | Inbound SCIM 2.0 server (for HRIS or another IdP as the source of truth) | P1 | B |
| SCIM-04 | Non-SCIM connectors via API adapters (Slack, GitHub orgs) | P2 | B |

### 5.10 Conditional access (`CA`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| CA-01 | Rules over user/group, application, device (managed, compliant, OS), network (IP/geo), risk and time | P0 | A |
| CA-02 | Outcomes: allow, require MFA, require a compliant device, block, and allow with session limits | P0 | A |
| CA-03 | **What-if simulator**: pick a user, app, device and context and see which rules match and the final decision | P0 | A |
| CA-04 | Report-only mode for new rules, with an impact dashboard | P0 | A |
| CA-05 | Device trust in the browser: the agent attests the device during SSO (local loopback or a browser extension handshake) | P0 | A |

### 5.11 Access requests and JIT (`JIT`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| JIT-01 | Users request an app, group, admin role or **agent tool grant** with a justification and duration | P0 | B |
| JIT-02 | Approval chains: manager, resource owner, specific group; multi-stage | P0 | B |
| JIT-03 | Approve or deny from Slack and Teams | P1 | B |
| JIT-04 | Automatic expiry and revocation; the audit record links request, approval, grant and revoke | P0 | B |
| JIT-05 | Periodic access reviews (certification campaigns) | P1 | B |

### 5.12 Agent identities (`AGT`), differentiator

| ID | Requirement | Pri | Release |
|---|---|---|---|
| AGT-01 | Register an agent: name, description, **owner** (user or group), environment, runtime/model, risk tier, tags | P0 | A |
| AGT-02 | Agent credentials: OAuth client credentials, **private-key JWT**, and workload identity federation (GitHub Actions OIDC, AWS/GCP/K8s service-account tokens), so no static secrets are needed | P0 | A |
| AGT-03 | Short-lived access tokens (default 15 min) with an audience-bound scope | P0 | A |
| AGT-04 | **On-behalf-of delegation**: the agent exchanges a user token for a downscoped token (RFC 8693 token exchange) carrying an `act` claim; effective permission = agent ∩ user | P0 | B |
| AGT-05 | Human-in-the-loop consent: the first use of a sensitive scope on behalf of a user triggers a consent prompt (portal, push or Slack) | P1 | B |
| AGT-06 | **Kill switch**: instantly revoke all tokens and sessions for an agent (or all agents of an owner); propagates to gateways in < 5 s | P0 | A |
| AGT-07 | Agent lifecycle: an owner's offboarding forces reassignment or suspension; stale agents (no activity for N days) are flagged | P0 | B |
| AGT-08 | Agent inventory from discovery: agents seen at the MCP Gateway without registration show as **unmanaged** | P1 | B |
| AGT-09 | Per-agent activity timeline: tokens issued, tools called, data classifications touched, guardrail hits | P0 | B |
| AGT-10 | Agent-to-agent calls carry a delegation chain (`act` nesting); policy can limit chain depth | P1 | B |

### 5.13 MCP Gateway (`MCP`), differentiator

| ID | Requirement | Pri | Release |
|---|---|---|---|
| MCP-01 | Register upstream MCP servers (streamable HTTP; stdio via a sidecar) with their credentials, held in the vault and never exposed to clients | P0 | A (HTTP) · B (stdio) |
| MCP-02 | Auto-discover tools, resources and prompts; detect schema changes (**tool drift**) and require re-approval of changed tools | P0 | B |
| MCP-03 | The gateway acts as an MCP authorization server per the MCP auth spec (OAuth 2.1, protected resource metadata, dynamic client registration gated by admin policy) | P0 | A |
| MCP-04 | Per-tool authorization via Cedar: principal (agent/user/delegation), tool, arguments (e.g. `repo` in an allowlist), device posture, time | P0 | A |
| MCP-05 | Virtual MCP servers: combine tools from many upstreams into one curated endpoint per team or agent | P1 | B |
| MCP-06 | Request and response inspection hooks into Guardrails (`GRD`), with block, redact or allow-and-flag outcomes | P0 | B |
| MCP-07 | Rate limits and quotas per agent, tool and tenant | P0 | B |
| MCP-08 | Full trace of every call (who, on behalf of whom, tool, args hash or redacted args, decision, latency, guardrail results) to the audit log | P0 | A |
| MCP-09 | Deploy options: Votal-hosted (multi-tenant) or customer-hosted (container/Helm) that pulls policy bundles and pushes events | P0 | B |
| MCP-10 | Tool risk classification (read / write / destructive / external-egress), set by default heuristics and overridable by admins | P1 | B |
| MCP-11 | A generic LLM API proxy mode (OpenAI/Anthropic-compatible) that applies identity, guardrails and logging to model calls | P2 | C |

### 5.14 Guardrails (`GRD`)

Integrates the existing **Votal Guardrails** engine as a service.

| ID | Requirement | Pri | Release |
|---|---|---|---|
| GRD-01 | DLP detectors: PII (email, phone, SSN, card), secrets (API keys, private keys), custom regex and dictionary | P0 | B |
| GRD-02 | Prompt-injection and tool-poisoning detection on tool descriptions and tool outputs | P0 | B |
| GRD-03 | Actions: block, redact, mask, alert, require approval | P0 | B |
| GRD-04 | Guardrail profiles assignable per MCP server, tool or agent | P0 | B |
| GRD-05 | Latency budget: inline checks p95 < 10 ms; heavier ML checks async (alert only) unless configured to block | P0 | B |

### 5.15 Audit, insights and SIEM (`AUD`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| AUD-01 | Every API mutation, auth event, policy decision (sampled for allows, 100% for denies), device command and MCP call is recorded as an immutable event | P0 | A |
| AUD-02 | Audit explorer: full-text and structured filter, time histogram, pivot by actor/target, saved searches; results in < 2 s over 90 days | P0 | A |
| AUD-03 | Retention: 90 days hot (default), 1 year+ on paid plans, with export to customer S3 | P0 | B |
| AUD-04 | SIEM streaming: Splunk HEC, Datadog, Sentinel, generic webhook, S3/GCS; OCSF-mapped schema | P0 | A (Splunk, webhook, S3) · B (rest) |
| AUD-05 | Tamper evidence: a hash chain per tenant per day, with the daily digest anchored and verifiable | P1 | B |
| AUD-06 | Reports: MFA coverage, device compliance, app access matrix, dormant accounts, agent-tool access matrix; CSV/PDF export | P1 | B |
| AUD-07 | **Access graph**: an explorable graph of who or what can reach which app, tool or data | P1 | B |
| AUD-08 | Alert rules on event patterns (e.g. > 5 denied tool calls in 1 min by one agent) to Slack, email or webhook | P1 | B |

### 5.16 Software and patch (`SW`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| SW-01 | Software inventory across the fleet, with version distribution and a known-vulnerable flag (CVE feed) | P1 | B |
| SW-02 | OS patch policies: deferral windows, maintenance windows, forced-restart deadlines | P1 | C |
| SW-03 | Third-party app deployment and updates (Homebrew/winget/choco-backed catalog) | P2 | C |

### 5.17 SaaS discovery (`SAAS`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| SAAS-01 | Discover SaaS use from the agent (browser domains and OAuth grants) and from Google/M365 OAuth-grant APIs | P1 | C |
| SAAS-02 | Shadow-IT dashboard: app, users, first seen, managed vs. unmanaged, risk | P1 | C |
| SAAS-03 | Discover **AI tools** in use (ChatGPT, Claude, Copilot, Cursor, local MCP servers in configs) | P1 | B |

### 5.18 Integrations and notifications (`INT`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| INT-01 | Public REST API (OpenAPI 3.1) covering 100% of console functionality | P0 | A |
| INT-02 | API keys (scoped, expiring) and OAuth apps for API access | P0 | A |
| INT-03 | Outbound webhooks with signed payloads, retries and a delivery log | P0 | A |
| INT-04 | Slack and Microsoft Teams apps for notifications and approvals | P1 | B |
| INT-05 | Terraform provider and CLI (`nexus`) | P1 | B |

### 5.19 User portal (`PORT`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| PORT-01 | App launcher with search, favorites and recently used | P0 | A |
| PORT-02 | Security settings: MFA factors, passkeys, sessions, password | P0 | A |
| PORT-03 | My devices: compliance status with "how to fix" guidance | P0 | A |
| PORT-04 | Request access, see pending requests, approve requests (for approvers) | P0 | B |
| PORT-05 | My agents: agents I own or have delegated to, their grants, revoke delegation | P0 | B |

### 5.20 Legacy directory protocols (`LEG`)

| ID | Requirement | Pri | Release |
|---|---|---|---|
| LEG-01 | Cloud LDAP (LDAPS, read-only bind + search) for legacy apps and NAS | P1 | C |
| LEG-02 | Cloud RADIUS (EAP-TTLS/PAP, MFA push) for Wi-Fi and VPN | P1 | C |
| LEG-03 | Basic macOS MDM (ABM enrollment, configuration profiles, FileVault escrow) | P2 | C |

### 5.21 SecOps operability (`OPS`)

These requirements decide whether a security team *loves* the product or merely tolerates it. They cut across every module.

| ID | Requirement | Pri | Release |
|---|---|---|---|
| OPS-01 | **Secure baseline**: one click applies the recommended config (MFA for everyone, passkeys for admins, session limits, starter conditional-access rules in report-only mode), with a checklist of what changed | P0 | A |
| OPS-02 | **Posture score and "Needs attention" queue**: a ranked, actionable list (users without MFA, non-compliant devices, dormant admins, unowned agents), where each item has a one-click fix or deep link | P0 | A |
| OPS-03 | **Contain**: one action on a user, device or agent suspends it, revokes sessions and tokens, locks devices and kills owned agents. It is reversible ("Release") and records a case note. Available on web, mobile and the API | P0 | A |
| OPS-04 | **Explain everywhere**: every allow or deny (login, SSO, tool call, compliance) has a "Why?" trace listing the matched policies, the inputs, and what would change the outcome | P0 | A |
| OPS-05 | **Safe rollout for every policy type**: report-only mode, an impact preview ("affects 412 users, 37 would be blocked"), then enforce. Policies can be rolled back to any prior version | P0 | A |
| OPS-06 | **Config change history**: every admin change shows who, when and a diff, with one-click revert | P0 | A |
| OPS-07 | **Config as code**: Terraform provider, `nexus` CLI, and org config export/import (YAML) for GitOps and staging-to-prod promotion | P1 | B |
| OPS-08 | **Low-noise alerting**: sensible default alert rules, deduplication, severity levels, snooze, and an "alert quality" view (which rules fire most and get dismissed) | P0 | B |
| OPS-09 | **Investigation cases**: pin events across users, devices and agents into a case timeline, add notes, export an evidence pack (PDF/JSON) | P1 | B |
| OPS-10 | **Time to value**: a setup wizard takes a new org to its first SSO app plus MFA enforced plus a device enrolled in < 30 minutes | P0 | A |
| OPS-11 | **Least-privilege admin by default**: new admins get the narrowest role; a JIT admin elevation flow for break-fix | P1 | B |

### 5.22 Notifications (`NTF`)

A single pipeline serves every channel. Domain events → notification rules → per-recipient preferences → channels.

| ID | Requirement | Pri | Release |
|---|---|---|---|
| NTF-01 | Unified notification service: any domain event can trigger notifications through rules (built-in plus admin-defined), with recipients resolved from roles, owners, approvers or on-call | P0 | A |
| NTF-02 | **In-app inbox** shared by web and mobile: read/unread, archive, deep links, inline actions; the same list via `/v1/me/notifications` | P0 | A |
| NTF-03 | **Real-time** delivery to open web and mobile sessions via SSE (`/v1/me/stream`) | P0 | A |
| NTF-04 | **Mobile push** (APNs / FCM), **content-free**: the payload carries only an ID and a generic title; the app fetches details over the authenticated API | P0 | A |
| NTF-05 | **Browser Web Push** (VAPID + service worker) for admins with the console closed, also content-free | P1 | B |
| NTF-06 | Email and Slack channels; Microsoft Teams | P0 (email, Slack) · P1 (Teams) | A (email, Slack) · B (Teams) |
| NTF-07 | Per-user preferences per category × channel, quiet hours, and a digest option; **critical** security notifications can be forced by org policy | P0 | A |
| NTF-08 | **Actionable notifications** (approve/deny, acknowledge, contain) that require a fresh auth or step-up on the acting device; there are no bearer "magic links" for sensitive actions | P0 | A |
| NTF-09 | Grouping and deduplication (e.g. "12 devices went non-compliant"), rate caps per recipient | P0 | B |
| NTF-10 | On-call routing: PagerDuty and Opsgenie for critical alerts, with acknowledgement synced back | P1 | B |
| NTF-11 | Delivery log per notification (channel, status, retries, read/acted) for admins and for debugging | P0 | A |

### 5.23 Mobile app (`MOB`)

**Nexus Mobile** (iOS + Android) has two roles: an **authenticator** for everyone and a **responder** for admins. It is not a full admin console.

| ID | Requirement | Pri | Release |
|---|---|---|---|
| MOB-01 | Sign in with OIDC auth code + PKCE via the system browser (passkeys work there); biometric app lock; tokens in Keychain / Keystore | P0 | A |
| MOB-02 | **Authenticator**: push MFA with number matching, where approval is signed by a Secure Enclave / StrongBox key behind a biometric check; offline TOTP codes as fallback | P0 | A |
| MOB-03 | Notification inbox and push (NTF-02, NTF-04), with deep links into the relevant screen | P0 | A |
| MOB-04 | **Responder quick actions** with step-up: contain a user, device or agent (OPS-03); agent kill switch; revoke sessions | P0 | A |
| MOB-05 | Global search across users, devices and agents, with read-only detail views (status, signals, recent activity) | P0 | A |
| MOB-06 | Approve or deny access requests and two-person command approvals | P0 | B |
| MOB-07 | Alert triage: alert detail with event context, acknowledge, snooze, escalate, add to case | P0 | B |
| MOB-08 | End-user self-service: my apps, my devices and how to fix compliance issues, my agent delegations | P1 | B |
| MOB-09 | App hardening: jailbreak/root detection (a risk signal, not a hard block), certificate pinning, screenshot blocking on sensitive screens, minimal encrypted cache | P0 | A |
| MOB-10 | Minimum-version enforcement: the API can require an app update for security fixes | P0 | A |

## 6. Non-functional requirements

| Area | Requirement |
|---|---|
| **Availability** | Auth/SSO, token and MCP Gateway paths: 99.95% monthly. Admin console/API: 99.9%. |
| **Latency** | Login page TTFB p95 < 300 ms. Token issuance p95 < 100 ms. Policy decision p99 < 5 ms (in-process). MCP Gateway added overhead p95 < 15 ms (excluding guardrail ML). Console list views p95 < 500 ms. |
| **Scale (v1 target)** | 5,000 tenants; 200k users; 250k devices total (50k per tenant); 2,000 MCP calls/s per region; 50k concurrent agent connections per device-gateway node. |
| **Security** | Tenant isolation enforced in the DB (Postgres RLS) **and** in the app layer. All data encrypted at rest (KMS envelope, per-tenant DEKs for secrets). TLS 1.3 only. Secrets never logged. Signed builds and SBOMs. External pentest before GA. |
| **Compliance** | SOC 2 Type II controls from day one (target report in month 12). GDPR: EU region, DPA, data export and erasure. |
| **Privacy** | MCP payload logging is **off by default**: arguments are hashed or redacted, and full capture is opt-in per server with a retention cap. |
| **Accessibility** | WCAG 2.2 AA for the console and portal; platform accessibility (VoiceOver / TalkBack, Dynamic Type) in the mobile app. |
| **Notifications** | Push MFA end-to-end (sign-in → phone prompt) p95 < 3 s. Critical alerts delivered to at least one channel within 30 s. |
| **Mobile** | iOS 17+ / Android 10+; cold start < 1.5 s; push MFA approval is ≤ 2 taps plus biometric. |
| **i18n** | All UI strings externalized; English at launch; ready for RTL. |
| **Operability** | OpenTelemetry traces, metrics and logs; SLO dashboards; runbooks for every alert. |
| **DR** | RPO ≤ 5 min, RTO ≤ 1 h; cross-AZ; daily restore tests. |
| **Agent footprint** | Idle CPU < 1%, RSS < 60 MB, network < 5 MB/day idle. |

## 7. Release exit criteria

| Release | Scope | Exit criteria (demo-able, tested, documented) |
|---|---|---|
| **Foundations** (wk 1–4) | Walking skeleton | A deployed staging environment where a user signs in to the web console with a passkey, gets a **push approval on the mobile app**, and the sign-in shows up in the audit log and the notification inbox on both web and mobile. That one flow exercises API, auth, web, mobile, notifications and audit end-to-end. |
| **A — the most important 30%** (mo 1–5) | Workforce identity + device trust + agent identity v1 + responder mobile app | A pilot SecOps team can: sign up → apply the secure baseline → sync users from Google/Entra → enforce passkey/push MFA → SSO into 10 catalog apps → enroll macOS/Windows devices → **block SSO from non-compliant devices** (report-only, then enforce) → register AI agents with federated credentials → gate MCP tools through the hosted gateway → get a Slack/push alert and **contain a user or agent from their phone** → stream everything to Splunk. **Outcome: 3–5 design partners in production.** |
| **B — 30% → 80%** (mo 6–11) | Enterprise lifecycle + AI security depth + SecOps workflows | SCIM to 10+ apps and one-click offboarding; JIT access requests with mobile/Slack approvals; device policy enforcement, commands and scripts; Linux agent; full MCP Gateway (drift review, guardrails, OBO delegation, self-hosted, rate limits); alert triage and investigation cases; access graph and reviews; Terraform. Latency NFRs met under load. **Outcome: GA and SOC 2 Type I.** |
| **C — long tail** (mo 12+) | Legacy and breadth | LDAP, RADIUS, patch management, app deployment, SaaS discovery, basic macOS MDM, MSP multi-org, LLM API proxy mode, SOC 2 Type II. |

## 8. Success metrics

- **Activation:** % of new orgs that enroll ≥ 1 device **and** enforce MFA within 7 days (target 40%).
- **Time to onboard a new hire** (created → apps provisioned + device enrolled): < 15 min.
- **Offboarding completeness:** 100% of app access revoked within 60 s of deprovision.
- **MFA coverage** across active users per tenant (target > 95%).
- **Agent governance:** % of MCP traffic from registered (vs. unmanaged) agents (target > 90%).
- **SecOps love:** median time to contain (alert → contained) < 2 min; > 60% of admins with the mobile app installed; alert dismiss rate < 30% (a low-noise signal).
- **End-user love:** push MFA approval rate > 98% with median < 5 s; < 1 helpdesk ticket per 100 users per month for login issues.
- **Reliability:** SLOs met; zero cross-tenant data incidents.

## 9. Open questions

1. **Pricing and packaging:** per user, per device, or per agent? Is MCP Gateway traffic metered?
2. **Guardrails integration:** is the existing Votal Guardrails engine a library (in-process in Go) or a service (gRPC)? This drives the latency budget.
3. **Browser device trust:** is a browser extension acceptable, or loopback only? (It affects Safari support.)
4. **Self-hosted gateway licensing and update channel**, including air-gapped support.
5. **Data residency beyond US/EU** (e.g. India, AU) in year 1?
6. **Which HRIS connectors come first:** Rippling, BambooHR or Workday?

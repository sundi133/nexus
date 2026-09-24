# Votal Nexus — UI / UX Specification

| | |
|---|---|
| **Status** | Draft v0.2 |
| **Date** | 2026-09-24 |
| **Related** | [SPEC.md](SPEC.md) · [ARCHITECTURE.md](ARCHITECTURE.md) |

---

## 1. Design principles

1. **Calm density.** Security admins scan lots of data. Tables are dense and readable, with generous whitespace *between* regions rather than inside rows. The look takes after Linear, Vercel and Tailscale, not a 2012 enterprise console.
2. **Keyboard first.** `⌘K` command palette for everything (navigate, search entities, run actions). `g u` → Users, `g d` → Devices, `/` → focus search, `j/k` to move in lists, `e` to edit, `?` shows shortcuts.
3. **Every decision is explainable.** Anywhere an access decision appears (denied login, blocked tool call, non-compliant device) there is a **"Why?"** link that opens the decision trace: the matched policies, the inputs, and what would change the outcome.
4. **Safe by default, fast when sure.** Destructive actions show the blast radius ("This will revoke 3 apps and 12 agent tokens"), need typed confirmation above a threshold, and can be undone where possible (soft-delete, 30-second undo toast).
5. **Progressive disclosure.** Visual builders for 90% of cases, and an "Advanced" toggle into raw Cedar / JSON / script for the rest.
6. **One pattern everywhere.** Every entity has the same **List → Detail** anatomy (§4). Learn it once and it works for users, devices, agents, apps and tools.
7. **Live.** Device online state, command output and the audit stream update in real time (SSE); no manual refresh.
8. **Light and dark** themes, first-class, following the system setting by default.

## 2. Frontend stack

| Concern | Choice |
|---|---|
| Framework | Next.js 15 App Router, React 19, TypeScript (strict) |
| Styling | Tailwind CSS v4 with design tokens as CSS variables |
| Components | shadcn/ui (Radix primitives), owned in `packages/ui` |
| Data fetching | TanStack Query on a generated OpenAPI client (`packages/api-client`); server components for first paint on list pages |
| Tables | TanStack Table v8 + virtualization (`@tanstack/react-virtual`) |
| Forms | react-hook-form + zod (schemas generated from OpenAPI where possible) |
| Command palette | `cmdk` |
| Charts | Recharts (standard charts); `visx` only for custom work |
| Graphs | React Flow (access graph, approval chains) |
| Code editors | Monaco (Cedar with a custom language + schema-aware completion, scripts) |
| Icons | Lucide |
| Motion | Framer Motion, subtle (150–200 ms), with `prefers-reduced-motion` respected |
| Testing | Vitest + Testing Library, Playwright E2E, Storybook with visual regression (Chromatic) and axe checks |

## 3. Information architecture

```
Votal Nexus  [org switcher]                         ⌘K Search…     🔔   (avatar)
───────────────────────────────────────────────────────────────────────────────
  Overview

  IDENTITY
    Users
    Groups
    Service identities

  DEVICES
    All devices
    Device policies
    Commands & scripts
    Software

  ACCESS
    Applications (SSO)
    Conditional access
    Access requests          (badge: pending count)
    Access reviews

  AI SECURITY
    Agents
    MCP servers
    Tools
    Guardrails
    Activity                 (live agent/tool call stream)

  INSIGHTS
    Audit log
    Access graph
    Reports
    Alerts

  SETTINGS
    Organization · Domains · Authentication · Admins & roles
    Integrations · API keys · Webhooks · Billing
```

The **user portal** (`/portal`) is a separate, simpler shell: **Apps · Devices · Requests · Agents · Security**.

## 4. Core layout patterns

### 4.1 List page

```
┌────────────────────────────────────────────────────────────────────────────┐
│ Users                                               [Import]  [+ New user] │
│ 1,284 users · 1,190 active · 23 suspended                                  │
├────────────────────────────────────────────────────────────────────────────┤
│ 🔍 Search…   [Status ▾] [Group ▾] [MFA ▾] [+ Filter]   Saved views ▾   ⚙︎ │
├──┬─────────────────────┬────────────┬──────────┬──────────┬───────────────┤
│☐ │ Name                │ Status     │ MFA      │ Devices  │ Last login    │
├──┼─────────────────────┼────────────┼──────────┼──────────┼───────────────┤
│☐ │ (A) Ana Ruiz        │ ● Active   │ Passkey  │ 2 ✓      │ 4 min ago     │
│☐ │ (B) Ben Ota         │ ● Active   │ ⚠ None   │ 1 ✗      │ 2 days ago    │
│  │ …                                                                       │
└──┴─────────────────────┴────────────┴──────────┴──────────┴───────────────┘
  Selecting rows reveals the bulk bar: [Add to group] [Suspend] [Reset MFA] [Export]
```

- Filters are chips that are **encoded in the URL** (shareable), and saved views are per admin or shared.
- Column picker; sticky header; virtualized rows; row click opens the detail page, and `⌥+click` opens a **peek drawer**.
- Empty states teach: an illustration, one sentence, and a primary action ("Enroll your first device").

### 4.2 Detail page

```
┌────────────────────────────────────────────────────────────────────────────┐
│ ← Users / Ana Ruiz                                  [Actions ▾]  [Edit]    │
│ (A) Ana Ruiz  ● Active   ana@acme.com · Eng · Manager: Kim Lee             │
│ ┌ Signals ─────────────────────────────────────────────────────────────┐   │
│ │ MFA: Passkey ✓   Devices: 2 compliant   Apps: 14   Agents owned: 3   │   │
│ └──────────────────────────────────────────────────────────────────────┘   │
│ [Overview] [Groups] [Apps] [Devices] [Agents] [Sessions] [Activity]        │
├────────────────────────────────────────────────────────────────────────────┤
│ tab content                                        │ Side panel:           │
│                                                    │ attributes, IDs,      │
│                                                    │ created/updated       │
└────────────────────────────────────────────────────────────────────────────┘
```

- The **Activity** tab on every entity is a filtered audit-log view.
- The **Actions** menu is permission-aware and shows keyboard shortcuts.

### 4.3 Global elements
- **Command palette (`⌘K`):** entities (fuzzy search across users, devices, agents, apps, tools), navigation, and actions ("Suspend user…", "Run script on…", "Kill agent…").
- **Notifications:** approvals waiting for you, failed SCIM syncs, drift reviews, alerts.
- **Toasts** carry an undo action where possible.
- **Step-up modal** appears inline when an action needs fresh MFA; the action resumes after it succeeds.

## 5. Key screens

### 5.1 Overview (home)

```
┌ Needs attention ───────────────────────────────────────────────────────────┐
│ ⚠ 37 users without MFA  →   ⚠ 12 non-compliant devices  →                  │
│ ⚠ 4 tools pending drift review  →   ⏳ 6 access requests awaiting you  →   │
└────────────────────────────────────────────────────────────────────────────┘
┌ Identity ──────────┐ ┌ Devices ───────────┐ ┌ AI security ───────────────┐
│ 1,284 users        │ │ 1,402 devices      │ │ 58 agents · 9 unmanaged    │
│ MFA 96% ▁▂▃▅▇      │ │ Compliant 91%      │ │ 212k tool calls (24h)      │
│ Logins 24h 4,210   │ │ Online 1,130       │ │ Blocked 143 · Redacted 51  │
└────────────────────┘ └────────────────────┘ └────────────────────────────┘
┌ Activity (live) ───────────────────────────────────────────────────────────┐
│ 12:04  agent release-bot → github.merge_pr  ✗ denied (policy: prod-merge)  │
│ 12:03  Ben Ota signed in to Slack from MacBook-042 ✓                       │
└────────────────────────────────────────────────────────────────────────────┘
```

The "Needs attention" cards are the product's to-do list, and each one deep-links to a pre-filtered list.

### 5.2 Device detail
Tabs: **Overview** (hardware, OS, user, last seen, live status) · **Compliance** (per-policy status with a "Why?" link and remediation) · **Software** · **Commands** (history + run new) · **Security** (encryption, firewall, EDR, admin accounts) · **Activity**. Header actions: Lock, Restart, Run script, Wipe (typed confirmation), Remove.

### 5.3 Device policy editor
Pick a template → a form of settings with platform chips (macOS / Windows / Linux, where each setting shows which platforms it supports) → assign to groups → mode (**Audit** / **Enforce**) → **impact preview** ("Applies to 412 devices; 37 currently non-compliant").

### 5.4 Conditional access builder

```
IF  users in   [Engineering ×] [Contractors ×]
AND app is     [GitHub ×] [AWS ×]
AND device     [is not compliant ▾]
THEN           [Block ▾]           Mode: ◉ Report-only  ○ Enforce

[ View as Cedar ]                         ┌ What-if ───────────────────────┐
                                          │ User  [Ben Ota        ▾]       │
                                          │ App   [GitHub         ▾]       │
                                          │ Device[MacBook-042    ▾]       │
                                          │ → ✗ BLOCK  (matched: rule #3)  │
                                          └────────────────────────────────┘
```

### 5.5 Agent detail (AI security)
Header: name, owner, risk tier, status, and a **big red "Kill switch"** (step-up plus reason, then revokes everything in < 5 s).
Tabs:
- **Overview:** purpose, runtime/model, environment, last active, delegation mode.
- **Credentials:** federation trusts (e.g. "GitHub Actions: `repo:votal-ai/app:ref:refs/heads/main`"), keys, secret expiry.
- **Tool access:** a matrix of MCP servers × tools with allow / deny / conditional state; conditional cells open the policy.
- **Delegations:** users who have delegated to this agent, with scopes and expiry.
- **Activity:** a timeline of tool calls with decision, guardrail hits and latency; clicking a row opens the full trace (redacted args, matched policies, guardrail findings).

### 5.6 MCP server detail
Connection status, transport and deploy mode (hosted / self-hosted gateway health) · **Tools** table (risk, data class, status `approved` / `pending_review` / `blocked`, callers in the last 24 h) · **Drift review**: a side-by-side diff of the old and new tool description and schema, with Approve / Block · Guardrail profile · Rate limits.

### 5.7 Audit log explorer
- Query bar with a structured filter language and autocomplete (`actor.type:agent outcome:denied tool:github.*`), plus a time range picker.
- Histogram of events over time (brush to zoom).
- Results table that expands inline to show the JSON event, with "Pivot on actor / target / session" actions.
- Save a search, turn it into an alert rule, or export it.

### 5.8 Access graph
React Flow canvas: pick a subject (user, agent or group) and see the reachable apps, tools and data classes through groups, roles and grants. Filter by path type and highlight **risky paths** (e.g. an agent → destructive tool reachable without approval).

### 5.9 Access requests inbox
A split view with the list of requests on the left and the request detail on the right: requester, resource, justification, duration, requester risk context (device compliance, recent activity), approval chain progress, and one-click Approve / Deny with a comment. Keyboard: `a` approve, `d` deny.

### 5.10 User portal
App launcher grid (search, favorites) · banner "Your device needs attention → fix" · My requests · My agents (revoke a delegation) · Security (passkeys, TOTP, sessions).

### 5.11 Onboarding (first-run)
A checklist on the Overview until it is complete: **Verify domain → Import users → Enforce MFA → Enroll a device → Connect an app → Register an agent / MCP server**. Each step is an inline wizard.

## 6. Visual design system

### 6.1 Tokens (CSS variables, light/dark)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#FFFFFF` | `#0B0C0E` | App background |
| `--bg-subtle` | `#F7F7F8` | `#111316` | Sidebar, table header |
| `--border` | `#E6E7EA` | `#23262B` | Dividers |
| `--fg` | `#0F1115` | `#EDEEF0` | Primary text |
| `--fg-muted` | `#5B606B` | `#9097A3` | Secondary text |
| `--primary` | `#4F46E5` (indigo-600) | `#818CF8` | Primary actions, focus |
| `--success` | `#16A34A` | `#4ADE80` | Compliant, allowed |
| `--warning` | `#D97706` | `#FBBF24` | Attention, pending |
| `--danger` | `#DC2626` | `#F87171` | Denied, destructive |
| `--agent` | `#7C3AED` | `#A78BFA` | AI/agent entities accent |

- **Type:** Inter (UI) with tabular numerals in tables; JetBrains Mono (code, IDs, policies). Scale 12/13/14/16/20/24/30; the base UI size is **14 px**.
- **Spacing:** 4 px grid. **Radius:** 6 px (controls), 10 px (cards). **Shadows:** minimal; elevation comes from borders.
- **Entity color language:** users are neutral avatars, devices carry OS glyphs, agents get a violet ✦ badge, and tools carry a risk-colored dot. The same encoding is used everywhere.
- **Status pills:** a dot plus a label, never color alone (a11y).

### 6.2 Component inventory (`packages/ui`)
AppShell, Sidebar, Topbar, CommandPalette, DataTable (filters, saved views, bulk bar, column picker), EntityHeader, StatCard, SignalStrip, Tabs, PeekDrawer, FilterChip, QueryBar, TimeRangePicker, StatusPill, RiskBadge, EntityAvatar, KeyValueList, JsonViewer, DiffViewer, CodeEditor (Cedar/script), RuleBuilder, WhatIfPanel, ApprovalChain, Timeline, EmptyState, ConfirmDialog (typed), StepUpDialog, Toast (with undo), Wizard, Checklist.

## 7. Designing for SecOps teams (and the people they protect)

Enterprise security tools usually fail in one of two ways: they are **noisy** (alert fatigue) or **opaque** (nobody can tell why something was blocked). Nexus designs against both.

| SecOps pain | Nexus answer | Req |
|---|---|---|
| "Setup takes a quarter" | Setup wizard plus a **Secure baseline** button: first SSO app, MFA enforced and a device enrolled in < 30 min | OPS-01, OPS-10 |
| "I don't know what to fix first" | **Needs attention** queue ranked by risk; every item has a one-click fix | OPS-02 |
| "Enforcing a policy might lock out the CEO" | Report-only → impact preview → enforce → one-click rollback, for *every* policy type | OPS-05 |
| "Why was this blocked?" (helpdesk ticket) | A **Why?** trace everywhere; end users see a plain-language reason and fix steps | OPS-04 |
| "The incident happened at 2 a.m. and I was on my phone" | **Contain** from the mobile app in 3 taps plus biometric | OPS-03, MOB-04 |
| "Alert spam" | Default rules tuned for signal, grouping, snooze, alert-quality view | OPS-08, NTF-09 |
| "Who changed this?" | Change history with diffs and revert on every setting | OPS-06 |
| "Clicking in a console doesn't scale" | Terraform, CLI, YAML export; every screen has "Copy as API call / Terraform" | OPS-07 |
| "Our SIEM is where we live" | Streaming from day one (Release A), OCSF schema | AUD-04 |

End users should barely notice the product:
- **Passkeys and push**, not codes. A push approval is one tap plus Face ID, with the number to match shown large.
- **Blocked? Here's how to fix it.** A block screen says what's wrong ("FileVault is off") with a button that opens the right system setting, not an error code.
- **Self-service everything:** MFA reset with manager approval, access requests, and device fixes, so helpdesk isn't needed.

## 8. Mobile app (Nexus Mobile)

Built with Expo / React Native. It shares `packages/api-client`, `packages/core` and `packages/tokens` with the web app, and uses native components for a native feel (no web views, except the OAuth system browser).

### 8.1 Navigation (bottom tabs)

| Tab | Everyone | Admins (by permission) |
|---|---|---|
| **Inbox** | Sign-in approvals, request outcomes, device warnings | + alerts, pending approvals, drift reviews |
| **Approve** | (hidden unless there are items) | Access requests, two-person command approvals (Release B) |
| **Search** | — | Users, devices, agents: detail + quick actions |
| **Codes** | TOTP codes (offline) | same |
| **Me** | My apps, devices, agents, security settings | same |

### 8.2 Key screens

```
┌─────────────────────────────┐   ┌─────────────────────────────┐   ┌─────────────────────────────┐
│        Sign-in request      │   │ ← Ben Ota          ● Active │   │   Contain Ben Ota?          │
│                             │   │ ben@acme.com · Eng          │   │                             │
│   Acme SSO → GitHub         │   │ MFA ✓  Devices 1 ✗  Agents 2│   │ This will:                  │
│   MacBook-042 · SF, US      │   │                             │   │ • Suspend the account       │
│   Chrome · just now         │   │ Recent                      │   │ • Revoke 4 sessions         │
│                             │   │ 12:03 SSO Slack ✓           │   │ • Lock MacBook-042          │
│   Tap the number shown      │   │ 11:58 MFA push denied ✗     │   │ • Kill 2 owned agents       │
│   on your screen            │   │ 11:57 Login new country ⚠   │   │                             │
│                             │   │                             │   │ Reason  [Suspicious login ] │
│    [ 27 ]  [ 64 ]  [ 81 ]   │   │ ┌─────────────────────────┐ │   │                             │
│                             │   │ │  Contain  │  Sessions   │ │   │  [ Contain with Face ID ]   │
│   [ Deny — this wasn't me ] │   │ └─────────────────────────┘ │   │  Reversible from web/mobile │
└─────────────────────────────┘   └─────────────────────────────┘   └─────────────────────────────┘
   Push MFA (MOB-02)                 Entity detail (MOB-05)            Contain (OPS-03 / MOB-04)
```

- **"Deny, this wasn't me"** on a push prompt raises a `security.alert` to admins automatically and offers the user a password reset.
- **Lock-screen notifications** show only generic text ("New sign-in request"); details appear after unlocking (content-free push).
- **Every destructive action** shows the blast radius and needs biometric step-up.

### 8.3 Shared vs. platform-specific code

| Layer | Shared across web and mobile | Platform-specific |
|---|---|---|
| API client, query hooks, cache keys | ✅ `packages/api-client` | — |
| Validation schemas, filter language, formatters, permission helpers | ✅ `packages/core` | — |
| Design tokens (colors, type scale, spacing) | ✅ `packages/tokens` | Mapped to Tailwind (web) and NativeWind (mobile) |
| UI components | ❌ (the densities and interaction models differ) | `packages/ui` (web, shadcn) · `apps/mobile/components` (RN) |
| Auth / token storage | ❌ | BFF cookie (web) · Keychain + DPoP (mobile) |
| Real-time | Shared SSE event types | `EventSource` (web) · RN SSE client (mobile, foreground) + push (background) |

## 9. Web notifications UX

- **Bell and inbox drawer** in the top bar: tabs for *For you* (approvals, alerts) and *Activity*, with inline actions (Approve / Contain / Acknowledge). It is the same record as the mobile inbox, so acting in one place clears it everywhere.
- **Toasts** for real-time events on the current screen (e.g. command finished).
- **Browser push** (Release B): opt-in prompt shown only after the admin's first critical alert, never on first load.
- **Settings → Notifications:** a category × channel matrix (In-app · Mobile push · Email · Slack · Browser), quiet hours, and org-forced critical categories shown as locked.

## 10. Accessibility and quality bars
- WCAG 2.2 AA: contrast ≥ 4.5:1, visible focus rings, full keyboard operability, ARIA via Radix, and screen-reader-labelled status.
- Performance budgets: console JS for first load ≤ 200 KB gzip; LCP < 1.5 s on a list page (cached); interaction latency < 100 ms.
- Every screen has a Storybook story, an axe check in CI, and a Playwright happy-path test.

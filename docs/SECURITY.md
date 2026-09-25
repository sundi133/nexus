# Security overview

This is for security reviewers and customers' security teams. It covers how Nexus protects tenants, credentials and secrets, and how we check that these controls stay in place. For how to run Nexus, see [OPERATIONS.md](OPERATIONS.md). For the design decisions, see [ARCHITECTURE.md](ARCHITECTURE.md), especially the ADRs.

## Reporting a vulnerability

Email **security@votal.ai** with the steps to reproduce. We acknowledge within 2 business days, give an initial assessment within 5, and aim to fix critical issues within 7 days. We credit reporters who want credit. Please don't access other customers' data, and don't degrade the service while testing.

## Tenant isolation

Every organization's data is separated in two independent layers.

1. **Database:** row-level security on every table.
   - The application connects as `nexus_app`, which is neither a superuser nor able to bypass RLS.
   - Every query runs in a transaction bound to one organization (`db.tenant(orgId, …)`).
   - Each table's policy compares `org_id` to that binding for both reads and writes.
   - A few cross-tenant operations exist, such as looking up a session by token hash, claiming background jobs, and checking whether a domain is claimed. Each is a narrow `SECURITY DEFINER` function with a fixed `search_path` and no `PUBLIC` execute right. Each returns only what that step needs.
2. **Application:** every route resolves the caller's organization from the credential, never from the request, and checks a permission (RBAC). Admin actions also require a recent MFA step-up. Owners can be required to use a passkey for it.

**Guards that fail the build if a control regresses** (`apps/api/test/security-guards.e2e.test.ts`, run in CI):
- Every table has RLS enabled and at least one policy, and every tenant table's policy is scoped to the current organization.
- The runtime role can't bypass RLS, and can't touch migration bookkeeping.
- Every `SECURITY DEFINER` function has a fixed `search_path` and isn't callable by `PUBLIC`.
- An unauthenticated request is made to every endpoint in the OpenAPI description (more than 140 operations). Each must be refused unless it's on a short, reviewed public list (sign-in, SSO protocol endpoints, agent enrollment and check-in, which use their own signed credentials). The public list must also match the API description.
- Cross-tenant tests in each feature suite try to read and change another organization's objects by ID.

## Authentication

- **Passwords:**
  - Hashed with Argon2id.
  - Checked against known breaches with the Have I Been Pwned k-anonymity range API. Only the first 5 characters of the SHA-1 hash leave the server. If the service is unreachable, the check is skipped.
  - Sign-in attempts are rate-limited per account and per IP.
- **MFA:**
  - Methods: passkeys (WebAuthn), TOTP, and push with number matching.
  - Single-use recovery codes, stored hashed.
  - Organizations can require MFA for everyone, and passkeys for owners.
  - Sensitive actions need a fresh step-up.
- **Sessions:**
  - Opaque tokens (`nxs_` + 256 random bits). Only a SHA-256 hash is stored, so a database leak yields no usable tokens.
  - Sessions expire idle and absolute (set per organization), and can be revoked individually or all at once ("sign out everywhere").
  - The console keeps the token in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie through its backend-for-frontend. Browser JavaScript never sees it.
- **API keys:**
  - Format `nxk_…`, stored hashed.
  - Each key has explicit scopes limited to what it can be granted, and always expires.
  - Rate-limited to 600 requests per minute. Every use is audited as the key itself.
- **Devices:** the agent enrolls with a single-use token and then signs every check-in with a device-bound ES256 key. The key's folder is readable only by root, or on Windows by SYSTEM and Administrators (not inherited from `ProgramData`). The Windows installer keeps the enrollment token out of its logs, and the agent deletes it after use. Agent updates are signed releases, verified before install.
- **Password reset:** single-use, short-lived links, stored hashed. The request always returns the same response, so it can't be used to discover which accounts exist. A reset signs out every session.
- **Sign-in through the organization's IdP (OIDC or SAML):**
  - Only for email domains the organization has verified by DNS. An IdP can only vouch for people in its own domains, so a compromised or misconfigured IdP can't sign in anyone else.
  - OIDC uses the authorization code flow with PKCE, state and nonce. ID tokens are checked against the IdP's published keys, issuer (from discovery, which must match exactly), audience and expiry. Emails the IdP marks unverified are refused.
  - SAML is SP-initiated only, so every response must answer a request we sent (InResponseTo), which also makes it single-use. Signatures are checked with the certificate on file (never one in the message; SHA-1 refused), and everything is read from the signed bytes, which defeats signature wrapping. Issuer, audience, recipient and time window are checked. Encrypted assertions are refused with an explanation.
  - Each sign-in is tied to the browser that started it by a short-lived cookie, which prevents login CSRF, and the state can be used only once.
  - The IdP's MFA counts only when the IdP reports it (`amr` or AuthnContext), unless an admin chooses otherwise.
  - Making an IdP *required* disables Nexus passwords, passkey sign-in and password resets for its domains. It needs a successful test sign-in since the last connection change. Break-glass accounts are exempt.
- **Inbound SCIM:** each SCIM connection has its own bearer token (stored as a SHA-256 hash, shown once, rotatable) that works only inside its organization. SCIM can't see or change break-glass accounts. Deactivations follow the connection's setting, and a burst of them (more than max(5, 10%) of people per hour) is paused until an admin approves. Every change is audited with the connection as the actor.
- **Break-glass accounts:** designated owners, exempt from directory sync and conditional access, so an SSO or directory outage can't lock everyone out. Every use alerts all admins with a critical alert and is audited.

## Secrets at rest

Secrets Nexus must use later are sealed with AES-256-GCM under a versioned key (`NEXUS_SEAL_KEYS`) that lives outside the database. This covers directory credentials, SCIM tokens, webhook secrets, SIEM tokens, TOTP seeds, OIDC signing keys and SAML keys.

- Keys rotate without downtime: add a new key, run `reseal`, retire the old key. See [OPERATIONS.md](OPERATIONS.md#key-rotation-seal-keys).
- Secrets we only need to compare are stored as hashes, never sealed: passwords, session and API key tokens, recovery codes, reset links.
- Secrets are shown once, when created, and never returned by the API afterwards.

## Outbound requests (SSRF)

Nexus calls customer-configured URLs: webhooks, SIEM endpoints, SCIM apps and Slack.

- Before every call, the URL must be `https` and resolve only to public addresses. Loopback, private, link-local (including cloud metadata `169.254.169.254`), CGNAT and IPv6 unique-local ranges are refused.
- Redirects are not followed.
- Private addresses are allowed only in development and tests. A production deployment refuses to start if that override is on.

## Audit and event streaming

- Every change is written to the audit log in the same database transaction as the change, so there is never a change without its record.
- Events carry the actor, IP, user agent and request ID.
- Events stream to SIEMs (Splunk HEC, Datadog, Microsoft Sentinel, or any HTTPS endpoint, with OCSF 1.3 mapping) with at-least-once delivery. The cursor can't skip events committed out of order.
- For long-term retention, events can also be archived to the customer's own S3 or Google Cloud Storage bucket. Turn on Object Lock or a retention policy there for tamper-proof (WORM) storage. The credentials Nexus needs only allow writing objects.
- Webhooks are signed with `nexus-signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`. Receivers should check the signature and reject timestamps older than 5 minutes.

## Web and API hardening

- **Headers:** HSTS, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (API) / `strict-origin-when-cross-origin` (console), and `frame-ancestors 'none'` / `X-Frame-Options: DENY`. In production, the console also sends a Content Security Policy.
- **CORS:** only the console's origin.
- **Validation:** request bodies are validated against strict schemas (zod/OpenAPI), and database access uses parameterized queries only (Kysely).
- **Startup checks:** production refuses to start on unsafe configuration: missing or weak seal keys, non-HTTPS public URLs, default database passwords, private outbound access, or a missing metrics token.
- **Containers:** images run as a non-root user.

## Admin safety

- Admin actions need an MFA step-up; owners can be required to use a passkey.
- Settings changes are recorded with before and after values, and can be undone from the change history.
- Directory syncs are held when they would suspend more than max(5, 10%) of users, until an admin approves the exact count.
- Organizations can restrict sign-up and invitations to domains verified by DNS TXT records. Each domain can be claimed by only one organization.

## Dependencies and supply chain

- The lockfile is frozen in CI (`pnpm install --frozen-lockfile`).
- CI runs `pnpm audit` and fails on high or critical advisories.
- Base images are the official Node 24 and Postgres 16 images.
- Agent releases are signed with Ed25519 release keys and verified by devices before install. Devices roll back automatically if the new version fails to check in.

## Scope for penetration tests

**In scope:**
- The API (`/v1/*`, including the SSO protocol endpoints) and the console.
- The agent's enrollment, check-in and update flows.
- Tenant isolation, with at least two test organizations.
- Authentication and MFA flows, account recovery, and API keys.
- SSRF through configurable URLs.

**Out of scope:** denial-of-service volume tests, social engineering, and third-party services (identity providers, APNs/FCM, SIEMs).

Provide testers with two organizations, an owner and a member in each, an enrolled test device, and a webhook destination they control.

## Known limitations

These are tracked on the [roadmap](ROADMAP.md):
- AI-agent identities and MCP authorization are not built yet.
- Self-hosted deployments rely on the operator for database encryption at rest and network isolation.
- Two moderate advisories remain in mobile app build tooling. They don't ship to the server or the console.

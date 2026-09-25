# Operating Votal Nexus

How to deploy, run, observe, back up and recover Nexus. For the security model, see [SECURITY.md](SECURITY.md).

## Components

| Process | Image | Role | Scales |
|---|---|---|---|
| API | `deploy/docker/api.Dockerfile` | `NEXUS_ROLE=api`: HTTP API, SSE, OIDC/SAML protocol endpoints | Horizontally, stateless |
| Worker | same image | `NEXUS_ROLE=worker`: background jobs (directory sync, SCIM, webhooks/SIEM, notifications, rollouts, domain checks) | Horizontally. Jobs are claimed with `SKIP LOCKED`, and runs of the same key are serialized |
| Migrations | same image | `node dist/cli/migrate.js`: run once per release, before the rollout | One at a time (advisory lock) |
| Console | `deploy/docker/web.Dockerfile` | Next.js console and BFF, which holds session cookies | Horizontally, stateless |
| Postgres 16 | managed | All state. Row-level security isolates tenants | Vertically, with read replicas later |

`NEXUS_ROLE=all` runs the API and the worker in one process, for small installs and development.

## Deploying

- **Single host:** `deploy/compose/docker-compose.prod.yml` runs Postgres, migrations, two API replicas, a worker, the console, and Caddy with automatic HTTPS.
  1. Copy `deploy/compose/prod.env.example` to `prod.env` and fill it in.
  2. Run `docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/prod.env up -d --build`.
- **Kubernetes or ECS:** run the same images. Use `/healthz` for liveness and `/readyz` for readiness; readiness fails if the database is unreachable or the schema is behind the build. Run the migration command as a pre-rollout job.
- **Smoke test:** `deploy/compose/smoke-test.sh` builds the images, boots them in production mode, and checks readiness, signup, authentication, deny-by-default, metrics auth and security headers. CI runs it on every change.

Production refuses to start on unsafe settings. It lists every problem at once, for example a missing seal key, non-https URLs, default database passwords, a missing metrics token, or outbound private-network access left enabled.

### Configuration

| Variable | Purpose |
|---|---|
| `NEXUS_ENV` | `prod` in production (the images default to it) |
| `NEXUS_DATABASE_URL` / `NEXUS_DATABASE_OWNER_URL` | Runtime role `nexus_app` (always subject to RLS) / owner role for migrations and `reseal` |
| `NEXUS_PUBLIC_URL` / `NEXUS_API_PUBLIC_URL` | Console origin (OIDC issuer, links, CORS, the agent's allowed origin) / API origin (phones, agents) |
| `NEXUS_SEAL_KEYS` | `id:base64,…`, current key first. Encrypts stored secrets (see Key rotation) |
| `NEXUS_SMTP_URL`, `NEXUS_MAIL_FROM` | Transactional email (invitations, resets, alerts) |
| `NEXUS_METRICS_TOKEN` | Bearer token Prometheus uses to scrape `/metrics` |
| `NEXUS_ROLE` | `api`, `worker` or `all` |
| `NEXUS_TRUST_PROXY` | `true` behind your load balancer, so client IPs come from `X-Forwarded-For` |
| `NEXUS_APNS_*`, `NEXUS_FCM_SERVICE_ACCOUNT` | Mobile push. Without them, push is disabled in production |
| `NEXUS_AGENT_RELEASES_DIR`, `NEXUS_AGENT_RELEASE_KEYS` | Signed agent releases (see `agent/README.md`) |
| `NEXUS_LOG_FORMAT` | `json` (production default) or `pretty` |

## Observing

- **Logs:** one JSON line per request with `request_id`, `route` (the template, never raw IDs), `status`, `ms`, `org_id`, `actor` and `ip`. The same request ID is returned in `X-Request-Id` and stored on audit events.
- **Metrics** (`/metrics`, bearer token; keep it off the public edge, as the Caddyfile does):
  - `nexus_http_requests_total{method,route,status}` and `nexus_http_request_duration_seconds` (histogram)
  - `nexus_job_runs_total{kind,result}` and `nexus_job_duration_seconds`
  - `nexus_jobs{status,kind}`: queue depth and dead jobs
- **Suggested alerts:**
  - 5xx ratio above 1% for 5 minutes.
  - p95 latency above 500 ms on `/v1/sso/*` or `/v1/agent/checkin`.
  - `nexus_jobs{status="queued"}` growing for 15 minutes (workers down or behind).
  - `nexus_jobs{status="dead"}` increasing.
  - `/readyz` failing.
- **Product-level health** is also shown to customers' admins in the console: directory sync status, provisioning errors, stream delivery backlog, rollout halts.

## Backups and recovery

- **Primary:** use the database's point-in-time recovery (managed Postgres with WAL archiving). The target from the spec is RPO ≤ 5 minutes and RTO ≤ 1 hour.
- **Second line:** portable, restore-tested logical backups.
  - Back up with `deploy/ops/backup.sh ./backups`. It writes a custom-format dump plus a SHA-256 checksum. Set `DATABASE_URL`, or `PG_CONTAINER` to use the tools inside a container.
  - Test the restore with `deploy/ops/restore-test.sh ./backups/nexus-….dump`. It checks the checksum, restores into a scratch database, and verifies the schema version, row-level security and policies on every table, and row counts. Then it drops the scratch database. CI runs this on every change; run it weekly against production backups and keep the output as evidence.
- **Keys are not in backups.** Stored secrets are sealed with the seal keys, which live in your secret manager. Keep the keys backed up separately, and keep old keys until `reseal` has run.
- **Restore procedure:**
  1. Restore the database (PITR to just before the incident, or from a dump).
  2. Set the same `NEXUS_SEAL_KEYS`.
  3. Deploy the matching release. `/readyz` confirms the schema.
  4. Directory sync and SCIM reconcile converge apps on their next run. Event streams resume from their cursors.

## Key rotation (seal keys)

1. Generate a key: `openssl rand -base64 32`.
2. Put it first: `NEXUS_SEAL_KEYS=2:<new>,1:<old>`. Roll out; new secrets use key 2 and old ones still open.
3. Run `pnpm --filter @nexus/api reseal --dry-run`, then `pnpm --filter @nexus/api reseal`. The same `node dist/cli/reseal.js` ships in the image. It re-encrypts every sealed secret with key 2 (use `--org=<id>` to go tenant by tenant). It exits non-zero and lists anything it couldn't open.
4. Remove key 1 once reseal reports nothing left, then roll out.

Other rotations are built into the product:
- OIDC signing keys and SAML certificates: Organization → SSO certificates and keys, with an overlap window.
- API keys: expiring by design.
- Webhook secrets, SCIM tokens and directory credentials: replace them in their settings.

## Capacity (load test)

Run with `node deploy/ops/loadtest.mjs --api <url> --seconds 20 --concurrency 32`. It sets up its own organization through the public API.

Measured on a single development API process (Apple M3 laptop, Postgres in Docker), with zero errors:

| Scenario | Throughput | p50 | p95 | p99 |
|---|---|---|---|---|
| Agent check-in (ES256-signed, posture evaluation) | 924 req/s | 31 ms | 53 ms | 73 ms |
| Authenticated read, `GET /v1/users?limit=50` | 1,103 req/s | 26 ms | 44 ms | 64 ms |
| OIDC authorize decision (policy evaluation, code issued) | 803 req/s | 35 ms | 61 ms | 80 ms |

- At one check-in per device per minute, one API process handles about 55,000 devices.
- API keys are limited to 600 requests per minute per key. The load test verifies that the limit holds.
- Production numbers depend on the database tier. Re-run the load test after sizing changes.

## Incident quick reference

| Situation | Where |
|---|---|
| Compromised account | User → Actions → Contain: suspend, sign out everywhere, deactivate app accounts |
| Leaver | User → Offboard, now or on a date |
| Everyone locked out (SSO, directory or MFA outage) | Sign in with the break-glass account (sealed password and key). Every use alerts all admins |
| Bad directory sync scope | Held automatically above the safety limit. Fix the scope, or approve the exact count |
| Bad agent release | Devices roll themselves back; the rollout halts. Agent updates → Cancel |
| Settings change went wrong | Organization → Change history → Undo |
| SIEM or webhook outage | Events queue behind the cursor; nothing is lost. The destination is turned off after 100 failures and resumes when turned back on |

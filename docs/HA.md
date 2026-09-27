# High availability

Nexus is built so that no single pod, node or zone failure, rollout, or database failover takes it down. It runs as stateless processes in front of one Postgres. The Helm chart in `deploy/helm/nexus` deploys it that way. CI proves it on every change with a drill on a real cluster.

## How it's built for it

| Part | Replicas (chart default) | Shared through Postgres |
|---|---|---|
| API (`NEXUS_ROLE=api`) | 3, spread across zones and nodes | Sessions, rate limits, SSE fan-out (`LISTEN/NOTIFY`), agent nonces |
| Worker (`NEXUS_ROLE=worker`) | 2 | Jobs are leased (`SKIP LOCKED`, 5-minute lease). Periodic work runs once per interval across all workers, on a clock kept in the database |
| Console (Next.js) | 2 | Nothing: stateless |
| Migrations | a Job per release | One at a time (advisory lock) |
| Postgres | managed, highly available | All state |

Any pod can serve any request, and any worker can run any job. There's no leader to elect: a worker that dies mid-job leaves a lease that expires, and another worker runs the job again (handlers are idempotent).

## Deploying with Helm

```bash
kubectl create secret generic nexus --from-literal=databaseUrl=postgres://nexus_app:…@db:5432/nexus \
  --from-literal=databaseOwnerUrl=postgres://nexus_owner:…@db:5432/nexus \
  --from-literal=sealKeys=1:$(openssl rand -base64 32) --from-literal=smtpUrl=smtps://… \
  --from-literal=metricsToken=$(openssl rand -hex 24)
helm install nexus deploy/helm/nexus \
  --set publicUrl=https://nexus.example.com --set apiPublicUrl=https://api.nexus.example.com \
  --set secret.existingSecret=nexus \
  --set ingress.enabled=true,ingress.className=nginx,ingress.consoleHost=nexus.example.com,ingress.apiHost=api.nexus.example.com
```

Prefer a Secret managed by your secret manager (External Secrets, Vault, Sealed Secrets) over `--from-literal`. Everything else is in [`values.yaml`](../deploy/helm/nexus/values.yaml): autoscaling, network policies, a Prometheus Operator `ServiceMonitor`, and a volume holding signed agent releases.

**Database roles, once:** the migration role owns the schema, and the application's role is subject to row-level security:

```sql
CREATE ROLE nexus_owner LOGIN PASSWORD '…';
CREATE ROLE nexus_app LOGIN PASSWORD '…';          -- no superuser, no BYPASSRLS
CREATE DATABASE nexus OWNER nexus_owner;
GRANT CONNECT ON DATABASE nexus TO nexus_app;
```

Only the migration Job receives the owner's credentials. The API and workers run with `nexus_app` alone.

**What the chart sets up:**
- **Probes.** Liveness is `/healthz`, the process itself. Readiness is `/readyz`: the database is reachable, the schema is current, and the pod isn't shutting down.
- **Rollouts** never go below full capacity (`maxUnavailable: 0`).
- **PodDisruptionBudgets** let node drains take one pod of each kind at a time.
- **Pods run locked down:** non-root, read-only root filesystem, all capabilities dropped, no service-account token.

## Rollouts without downtime

1. `helm upgrade` creates the release's migration Job and starts new pods beside the old ones.
2. A new pod reports ready only once the schema has reached its release's version. Until then the old pods keep serving. New workers wait for the migration before claiming jobs.
3. Old pods get SIGTERM. Readiness fails at once, and responses carry `Connection: close`. The pod keeps serving for 5 seconds (`api.shutdownDelaySeconds`) while the load balancer removes it. Then it stops accepting connections, gives requests in flight 10 seconds, and ends live streams (clients reconnect).

This relies on one rule: **migrations stay backward compatible**. The previous release keeps running on the new schema, first during the rollout and again after a `helm rollback`. So add columns and tables in one release, and drop or rename them one release after the code stops using them. A newer schema never makes a pod unready; only an older one does.

## What happens when things fail

| Failure | What users see | How it's handled |
|---|---|---|
| An API pod crashes | Requests in flight on that pod fail (clients retry); the rest are unaffected | Readiness removes it; Kubernetes replaces it |
| Node drain or upgrade | Nothing | The PodDisruptionBudget evicts one pod at a time; each drains first |
| A zone goes down | Nothing, if the database is multi-zone | Pods are spread across zones; the survivors take the load (turn on autoscaling for headroom) |
| A worker is killed | Background work pauses for seconds | The other workers continue; the dead worker's jobs rerun when their lease expires |
| Database failover (Multi-AZ) | Errors for the failover's duration (typically 30–120 s on managed Postgres) | Connections to the old primary fail fast (keepalive, 5 s connect timeout); pods go unready and come back on their own; no restarts |
| Database down for longer | The console and sign-ins fail; devices keep their last policy and retry | Everything recovers without intervention when it returns |
| Agent storm (a mass rollout, or everyone waking up after an outage) | The console stays fast | Agents get `503 busy` with a spread-out `Retry-After` beyond their share of connections ([OPERATIONS.md](OPERATIONS.md#fleet-simulator)) |

## Managed Postgres

- **Use a highly available tier:** Amazon RDS or Aurora Multi-AZ, Cloud SQL with HA, or Azure Database for PostgreSQL with zone-redundant HA. Postgres 16.
- **Turn on point-in-time recovery.** Targets: RPO ≤ 5 minutes, RTO ≤ 1 hour. Backups and restore tests are covered in [OPERATIONS.md](OPERATIONS.md#backups-and-recovery).
- **Size connections.** `max_connections` must exceed (API pods + worker pods) × `config.dbPoolSize` (default 20), plus the migration Job, plus about 10 for your own tools. With autoscaling, count the maximum number of API pods.
- **Connect directly, or through a pooler in session mode.** Nexus relies on session features: `LISTEN/NOTIFY` for live updates and an advisory lock for migrations. A transaction-mode pooler (PgBouncer's default) breaks them.
- **Cross-region disaster recovery** is active-passive: a cross-region read replica, promoted with DNS pointed at a standby deployment of the chart. Nexus doesn't automate this yet.

## Proving it: the HA drill

`deploy/helm/ci/drill.sh` installs the chart and then, under steady traffic from inside the cluster, does five things:

| Step | Must hold |
|---|---|
| Rolling restart of the API | 0 failed requests |
| An API pod is evicted (node maintenance); a second eviction is attempted meanwhile | 0 failed requests; the second eviction is refused |
| Upgrade to a release with a new migration | 0 failed requests; the migration runs once, as its own Job |
| A worker is killed without warning | The other worker keeps running; the dead one is replaced |
| The database is restarted | The API is ready again within seconds of the database; no API pod restarts |

CI runs it on a kind cluster for every change (job *Helm chart + HA drill*). To run it yourself:

```bash
kind create cluster --name nexus
docker build -f deploy/docker/api.Dockerfile -t votal/nexus-api:ci . && docker build -f deploy/docker/web.Dockerfile -t votal/nexus-web:ci .
printf 'FROM votal/nexus-api:ci\nCOPY 9999_drill.sql /app/migrations/\n' | docker build -t votal/nexus-api:ci2 -f - deploy/helm/ci
kind load docker-image votal/nexus-api:ci votal/nexus-api:ci2 votal/nexus-web:ci --name nexus
deploy/helm/ci/drill.sh
```

Run the same steps against staging before going live, and after major changes to the cluster or database. Use the load simulator (`nexus-loadsim`) as the traffic, so devices are part of the test.

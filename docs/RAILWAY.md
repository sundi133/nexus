# Deploying on Railway

Nexus runs on [Railway](https://railway.com) from this repository's Dockerfiles. Railway handles TLS and domains, so Caddy is not needed. The result is the same shape as `deploy/compose/docker-compose.prod.yml`:

| Service | Built from | Config file | Public domain |
|---|---|---|---|
| **Postgres** | Railway's Postgres template | — | none |
| **api** | `deploy/docker/api.Dockerfile` | `deploy/railway/api.json` | yes, e.g. `api.nexus.example.com`, port **8080** |
| **worker** | `deploy/docker/api.Dockerfile` | `deploy/railway/worker.json` | none |
| **web** | `deploy/docker/web.Dockerfile` | `deploy/railway/web.json` | yes, e.g. `nexus.example.com`, port **3100** |

The config files set the Dockerfile, the health check, and the restart policy for each service. The api config also runs migrations before each deploy.

## 1. Create the project

1. **New project → Deploy PostgreSQL.**
2. **New → GitHub repo →** this repository, three times. Name the services `api`, `worker` and `web`.
3. For each service, go to **Settings → Config-as-code** and set the config file path, for example `/deploy/railway/api.json`. Leave the root directory empty (the repository root), because the Dockerfiles build from there.

## 2. Create the runtime database role

The API connects as `nexus_app`, a role that is neither a superuser nor able to bypass row-level security. Tenant isolation depends on this, so never point `NEXUS_DATABASE_URL` at Railway's `postgres` user.

In the Postgres service, open **Database → Query**, or run `railway connect Postgres`, then run:

```sql
CREATE ROLE nexus_app LOGIN PASSWORD '<openssl rand -base64 32>';
GRANT CONNECT ON DATABASE railway TO nexus_app;
```

Railway's `postgres` user owns the schema and runs the migrations, like `nexus_owner` in the compose setup. The migrations grant `nexus_app` exactly what it needs.

## 3. Variables

Generate the secrets:

```bash
echo "1:$(openssl rand -base64 32)"   # NEXUS_SEAL_KEYS: keep a copy in your password manager
openssl rand -hex 24                  # NEXUS_METRICS_TOKEN (at least 24 characters)
```

Create a **shared variable** group for **api** and **worker**:

```
NEXUS_ENV=prod
NEXUS_DATABASE_URL=postgres://nexus_app:<password>@${{Postgres.RAILWAY_PRIVATE_DOMAIN}}:5432/${{Postgres.PGDATABASE}}
NEXUS_PUBLIC_URL=https://nexus.example.com
NEXUS_API_PUBLIC_URL=https://api.nexus.example.com
NEXUS_SEAL_KEYS=1:…
NEXUS_METRICS_TOKEN=…
NEXUS_MAIL_FROM=Nexus <no-reply@example.com>
NEXUS_RESEND_API_KEY=…            # or NEXUS_SMTP_URL=smtps://user:pass@smtp.example.com:465
NEXUS_TRUST_PROXY=true
NEXUS_SIGNUP=first
```

Per service:

| Service | Variables |
|---|---|
| api | `NEXUS_ROLE=api`, `NEXUS_DATABASE_OWNER_URL=${{Postgres.DATABASE_URL}}` (used only by the pre-deploy migration) |
| worker | `NEXUS_ROLE=worker` |
| web | `NEXUS_API_URL=http://${{api.RAILWAY_PRIVATE_DOMAIN}}:8080` |

- **Mobile push notifications:** also add `NEXUS_APNS_TEAM_ID`, `NEXUS_APNS_KEY_ID`, `NEXUS_APNS_KEY` and `NEXUS_FCM_SERVICE_ACCOUNT` to the shared group; see [MOBILE-PUSH.md](MOBILE-PUSH.md).
- **Signed agent releases:** add `NEXUS_AGENT_RELEASE_KEYS`.
- **Other settings:** [OPERATIONS.md](OPERATIONS.md) lists everything else.

## 4. Domains

- **api:** **Settings → Networking → Custom domain**, target port **8080**.
- **web:** the same, target port **3100**.

Add the CNAME records Railway shows. The domains must match `NEXUS_API_PUBLIC_URL` and `NEXUS_PUBLIC_URL` exactly, including `https://`.

## 5. Deploy and check

Deploy **api** first. Its pre-deploy step runs `node dist/cli/migrate.js`, and the deploy stops if the migration fails. Then deploy **worker** and **web**.

```bash
curl -s https://api.nexus.example.com/readyz   # {"ok":true,"schema":"…"}
```

In production the API refuses to start on unsafe settings and lists every problem in its deploy log: a missing seal key, http URLs, development database passwords, or a short metrics token. Fix them in Variables, and Railway redeploys.

Open `https://nexus.example.com` and sign up. The first organization makes you the owner. Then continue with step 2 of the [pilot guide](PILOT.md) (MFA, secure baseline, break-glass owner).

Point agents and Nexus Mobile at `https://api.nexus.example.com`.

## What works and what doesn't

| Feature | On Railway |
|---|---|
| Console, API, worker, agents, mobile pairing and push | Yes |
| Remote Assist | Yes. Its websocket relay shares the API port. Keep **one api replica**, or test it before scaling out, because both ends of a session must reach the same replica. |
| More api capacity | Raise `numReplicas` in `deploy/railway/api.json`, keeping the Remote Assist note above in mind. Workers can scale freely. |
| LDAP (`NEXUS_LDAP_PORT`) | Only through a Railway **TCP proxy**, on a port Railway picks. Clients must use that host and port. |
| RADIUS (`NEXUS_RADIUS_PORT`) | **No.** Railway doesn't accept inbound UDP. Run a second api container with `NEXUS_ROLE=api` and `NEXUS_RADIUS_PORT` on a host that does, pointed at the same database. |

## Backups and keys

- Turn on Railway's Postgres backups.
- Also keep portable dumps: run `DATABASE_URL=<Postgres public URL> deploy/ops/backup.sh ./backups`, and prove a dump restores with `deploy/ops/restore-test.sh` (see [OPERATIONS.md](OPERATIONS.md)).
- Backups don't include `NEXUS_SEAL_KEYS`. Without the keys, the stored secrets in a backup can't be decrypted, so keep a copy with your backups.
- To rotate keys, see Key rotation in [OPERATIONS.md](OPERATIONS.md). Run `reseal` from the api service's shell with `NEXUS_DATABASE_OWNER_URL` set.

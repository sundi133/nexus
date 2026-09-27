import { serve } from "@hono/node-server";
import { createApp, registerSchedules } from "./app.js";
import { useSharedRateLimits } from "./auth/ratelimit.js";
import { installOutboundGuard } from "./platform/outbound.js";
import { loadConfig, validateProd } from "./config.js";
import { Db } from "./platform/db.js";
import { JobRunner } from "./platform/jobs.js";
import { lifecycle } from "./platform/lifecycle.js";
import { sql } from "kysely";
import { LATEST_MIGRATION, migrate } from "./platform/migrate.js";
import { Realtime } from "./platform/realtime.js";
import { Sealer } from "./platform/seal.js";
import { SmtpMailer } from "./platform/mailer.js";
import { RecordingPushSender, RoutingPushSender } from "./platform/push.js";
import { ApnsSender } from "./platform/push-apns.js";
import { FcmSender } from "./platform/push-fcm.js";

const cfg = loadConfig();
const problems = validateProd(cfg);
if (problems.length) {
  console.error(`Refusing to start in production:\n${problems.map((p) => `  - ${p}`).join("\n")}`);
  process.exit(1);
}
// In production, migrations run as a separate release step (`pnpm --filter @nexus/api migrate`).
if (cfg.env !== "prod") await migrate(cfg.databaseOwnerUrl, (m) => console.log(`[migrate] ${m}`));

// API requests get 30 s per query; workers run long jobs (deleting an organization, retention).
const db = new Db(cfg.databaseUrl, { queryTimeoutMs: Number(process.env.NEXUS_DB_QUERY_TIMEOUT_MS) || (cfg.role === "api" ? 30_000 : 300_000) });
const realtime = new Realtime(cfg.databaseUrl);
const mailer = new SmtpMailer(cfg.smtpUrl, cfg.mailFrom);
// Real APNs/FCM when configured; otherwise pushes are logged (the app also gets challenges live over SSE).
const push = new RoutingPushSender(
  {
    ...(cfg.apns ? { ios: new ApnsSender(cfg.apns) } : {}),
    ...(cfg.fcmServiceAccount ? { android: FcmSender.fromServiceAccount(cfg.fcmServiceAccount) } : {}),
  },
  cfg.env === "prod" ? undefined : new RecordingPushSender(true),
);
if (cfg.env === "prod" && !cfg.apns) console.warn("[push] APNs is not configured: iOS pushes are disabled");
if (cfg.env === "prod" && !cfg.fcmServiceAccount) console.warn("[push] FCM is not configured: Android pushes are disabled");
const deps = { cfg, db, sealer: new Sealer(cfg.sealKeys), realtime, mailer, push };

const runsApi = cfg.role === "all" || cfg.role === "api";
const runsWorker = cfg.role === "all" || cfg.role === "worker";

// Workers serve only health and metrics over HTTP; API nodes serve everything.
// Booting while the database is down (an outage, a failover) mustn't crash-loop: readiness
// reports not-ready until it's back, and live updates connect when it is.
if (runsApi) realtime.startOrRetry();
// Rate limits count across every replica (login, MFA, API keys, MCP gateway...).
useSharedRateLimits(deps.db);
// Outbound HTTP checks the address it connects to (DNS rebinding) unless private access is allowed (dev).
installOutboundGuard(deps.cfg.allowPrivateOutbound);
const app = createApp(deps);
const jobs = runsWorker ? new JobRunner(deps) : null;
if (jobs) {
  registerSchedules(jobs, deps);
  // In production a rollout's migration runs beside the new pods: don't run jobs against the old schema.
  // (Health keeps answering meanwhile.)
  void (cfg.env === "prod" ? waitForSchema(deps.db) : Promise.resolve()).then(() => !stopping && jobs.start());
}

const server = serve({ fetch: app.fetch, port: cfg.port }, (info) => {
  console.log(`nexus ${cfg.role} listening on http://localhost:${info.port} (${cfg.env})`);
});
// Idle connections outlive the load balancer's (AWS ALB: 60 s), so it never reuses one this server
// has just closed (a 502 for the user).
Object.assign(server, { keepAliveTimeout: Number(process.env.NEXUS_KEEPALIVE_TIMEOUT_MS) || 65_000, headersTimeout: (Number(process.env.NEXUS_KEEPALIVE_TIMEOUT_MS) || 65_000) + 1000 });
server.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EADDRINUSE") {
    console.error(`Port ${cfg.port} is already in use. Stop the other process (lsof -i :${cfg.port}) or set NEXUS_PORT.`);
    process.exit(1);
  }
  throw err;
});

let stopping = false;
const shutdown = async (signal: string) => {
  if (stopping) return;
  stopping = true;
  console.log(`[${signal}] shutting down: finishing requests and jobs in flight`);
  const force = setTimeout(() => process.exit(1), 25_000).unref(); // orchestrators kill after ~30 s
  // Readiness fails from now on. Keep serving while the load balancer notices (Kubernetes takes a
  // few seconds to remove an endpoint), so no request is sent to a closed port.
  lifecycle.draining = true;
  const delay = Number(process.env.NEXUS_SHUTDOWN_DELAY_MS ?? (cfg.env === "prod" && runsApi ? 5000 : 0));
  if (delay > 0) await new Promise((r) => setTimeout(r, delay));
  const closed = new Promise<void>((r) => server.close(() => r()));
  const http = server as unknown as { closeIdleConnections?: () => void; closeAllConnections?: () => void };
  http.closeIdleConnections?.(); // idle keep-alive connections would otherwise hold the server open
  // Live streams (SSE) never finish by themselves; give ordinary requests 10 s, then end them (clients reconnect).
  const cut = setTimeout(() => http.closeAllConnections?.(), 10_000).unref();
  await closed;
  clearTimeout(cut);
  await jobs?.stop();
  if (runsApi) await realtime.stop();
  await db.close();
  clearTimeout(force);
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

async function waitForSchema(db: Db) {
  for (let logged = false; ; ) {
    const v = await db.unscoped(async (tx) => (await sql<{ v: string | null }>`SELECT nexus_schema_version() AS v`.execute(tx)).rows[0]!.v).catch(() => null);
    if (!LATEST_MIGRATION || (v ?? "") >= LATEST_MIGRATION) return;
    if (!logged) console.log(`[jobs] waiting for migrations: schema at ${v ?? "none"}, this release needs ${LATEST_MIGRATION}`);
    logged = true;
    await new Promise((r) => setTimeout(r, 2000));
  }
}

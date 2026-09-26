import { serve } from "@hono/node-server";
import { createApp, registerSchedules } from "./app.js";
import { useSharedRateLimits } from "./auth/ratelimit.js";
import { installOutboundGuard } from "./platform/outbound.js";
import { loadConfig, validateProd } from "./config.js";
import { Db } from "./platform/db.js";
import { JobRunner } from "./platform/jobs.js";
import { migrate } from "./platform/migrate.js";
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

const db = new Db(cfg.databaseUrl);
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
if (runsApi) await realtime.start();
// Rate limits count across every replica (login, MFA, API keys, MCP gateway...).
useSharedRateLimits(deps.db);
// Outbound HTTP checks the address it connects to (DNS rebinding) unless private access is allowed (dev).
installOutboundGuard(deps.cfg.allowPrivateOutbound);
const app = createApp(deps);
const jobs = runsWorker ? new JobRunner(deps) : null;
if (jobs) {
  registerSchedules(jobs, deps);
  jobs.start();
}

const server = serve({ fetch: app.fetch, port: cfg.port }, (info) => {
  console.log(`nexus ${cfg.role} listening on http://localhost:${info.port} (${cfg.env})`);
});
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
  await new Promise<void>((r) => server.close(() => r()));
  await jobs?.stop();
  if (runsApi) await realtime.stop();
  await db.close();
  clearTimeout(force);
  process.exit(0);
};
process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

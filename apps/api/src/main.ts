import { serve } from "@hono/node-server";
import { createApp, registerSchedules } from "./app.js";
import { JobRunner } from "./platform/jobs.js";
import { loadConfig } from "./config.js";
import { Db } from "./platform/db.js";
import { migrate } from "./platform/migrate.js";
import { Realtime } from "./platform/realtime.js";
import { Sealer } from "./platform/seal.js";
import { SmtpMailer } from "./platform/mailer.js";
import { RecordingPushSender } from "./platform/push.js";

const cfg = loadConfig();
if (cfg.env !== "prod") await migrate(cfg.databaseOwnerUrl, (m) => console.log(`[migrate] ${m}`));

const db = new Db(cfg.databaseUrl);
const realtime = new Realtime(cfg.databaseUrl);
await realtime.start();
const mailer = new SmtpMailer(cfg.smtpUrl, cfg.mailFrom);
const deps = { cfg, db, sealer: new Sealer(cfg.sealKey), realtime, mailer, push: new RecordingPushSender(true) };
const app = createApp(deps);
const jobs = new JobRunner(deps);
registerSchedules(jobs, deps);
jobs.start();

const server = serve({ fetch: app.fetch, port: cfg.port }, (info) => {
  console.log(`nexus api listening on http://localhost:${info.port} (${cfg.env})`);
});
server.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EADDRINUSE") {
    console.error(`Port ${cfg.port} is already in use. Stop the other process (lsof -i :${cfg.port}) or set NEXUS_PORT.`);
    process.exit(1);
  }
  throw err;
});

const shutdown = async () => {
  server.close();
  jobs.stop();
  await realtime.stop();
  await db.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

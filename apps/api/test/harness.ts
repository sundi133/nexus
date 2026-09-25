import * as OTPAuth from "otpauth";
import { randomBytes } from "node:crypto";
import { createApp } from "../src/app.js";
import { JobRunner } from "../src/platform/jobs.js";
import { loadConfig, type Config } from "../src/config.js";
import { Db } from "../src/platform/db.js";
import { migrate } from "../src/platform/migrate.js";
import { Realtime } from "../src/platform/realtime.js";
import { Sealer } from "../src/platform/seal.js";
import { MemoryMailer } from "../src/platform/mailer.js";
import { RecordingPushSender, type PushSender } from "../src/platform/push.js";

/** Boots the real app against the nexus_test database. Tests talk HTTP to it via app.request(). */
export async function bootApp(overrides: Partial<Config> = {}, opts: { push?: PushSender; resolveTxt?: (name: string) => Promise<string[][]> } = {}) {
  const cfg = { ...loadConfig(), ...overrides };
  await migrate(cfg.databaseOwnerUrl);
  const db = new Db(cfg.databaseUrl);
  const realtime = new Realtime(cfg.databaseUrl);
  await realtime.start();
  const mailer = new MemoryMailer();
  const recorder = new RecordingPushSender();
  const push = opts.push ?? recorder;
  const deps = { cfg, db, sealer: new Sealer(cfg.sealKey), realtime, mailer, push, resolveTxt: opts.resolveTxt };
  const app = createApp(deps);
  // Tests drive background work explicitly: jobs.runOnce({ orgId }).
  const jobs = new JobRunner(deps);

  async function call<T = any>(method: string, path: string, opts: { token?: string; body?: unknown } = {}) {
    const res = await app.request(path, {
      method,
      headers: {
        "content-type": "application/json",
        "user-agent": "nexus-tests",
        ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
    const text = await res.text();
    return { status: res.status, body: (text ? JSON.parse(text) : null) as T, headers: res.headers };
  }

  return {
    app,
    deps,
    jobs,
    call,
    mailer,
    push: recorder, // what was pushed when no custom sender is given
    close: async () => {
      await realtime.stop();
      await db.close();
    },
  };
}

export const uniqueEmail = (tag: string) => `${tag}-${randomBytes(4).toString("hex")}@example.test`;
export const PASSWORD = "correct-horse-battery-staple";

/** A TOTP code; `stepOffset: 1` gives the next 30s window (codes can't be reused within a window). */
export const totpCode = (secret: string, stepOffset = 0) =>
  new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), digits: 6, period: 30 }).generate({
    timestamp: Date.now() + stepOffset * 30_000,
  });

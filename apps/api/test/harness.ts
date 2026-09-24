import * as OTPAuth from "otpauth";
import { randomBytes } from "node:crypto";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { Db } from "../src/platform/db.js";
import { migrate } from "../src/platform/migrate.js";
import { Realtime } from "../src/platform/realtime.js";
import { Sealer } from "../src/platform/seal.js";
import { MemoryMailer } from "../src/platform/mailer.js";
import { RecordingPushSender } from "../src/platform/push.js";

/** Boots the real app against the nexus_test database. Tests talk HTTP to it via app.request(). */
export async function bootApp() {
  const cfg = loadConfig();
  await migrate(cfg.databaseOwnerUrl);
  const db = new Db(cfg.databaseUrl);
  const realtime = new Realtime(cfg.databaseUrl);
  await realtime.start();
  const mailer = new MemoryMailer();
  const push = new RecordingPushSender();
  const app = createApp({ cfg, db, sealer: new Sealer(cfg.sealKey), realtime, mailer, push });

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
    call,
    mailer,
    push,
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

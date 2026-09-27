import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RateLimiter, useSharedRateLimits } from "../src/auth/ratelimit.js";
import { Db } from "../src/platform/db.js";
import { loadConfig } from "../src/config.js";
import { bootApp, uniqueEmail } from "./harness.js";

/** Rate limits hold across API replicas (two processes = two app instances with separate memory). */

let a: Awaited<ReturnType<typeof bootApp>>;
let b: Awaited<ReturnType<typeof bootApp>>;
let db: Db;

beforeAll(async () => {
  a = await bootApp();
  b = await bootApp();
  db = new Db(loadConfig().databaseUrl);
  useSharedRateLimits(db);
});
afterAll(async () => {
  useSharedRateLimits(null);
  await db.close();
  await a.close();
  await b.close();
});

describe("shared rate limits", () => {
  it("count one window across limiter instances (as on separate replicas)", async () => {
    const name = `test-${randomUUID()}`;
    const r1 = new RateLimiter(3, 60_000, name);
    const r2 = new RateLimiter(3, 60_000, name);
    const key = "same-key";
    expect([await r1.take(key), await r2.take(key), await r1.take(key)]).toEqual([true, true, true]);
    expect(await r2.take(key)).toBe(false); // a fresh process would have allowed it
    expect(await r1.take("other-key")).toBe(true);
  });

  it("resets when the window ends", async () => {
    const r = new RateLimiter(1, 1000, `test-${randomUUID()}`);
    expect(await r.take("k")).toBe(true);
    expect(await r.take("k")).toBe(false);
    await new Promise((res) => setTimeout(res, 1100));
    expect(await r.take("k")).toBe(true);
  });

  it("stops password guessing that alternates between two API servers", async () => {
    const email = uniqueEmail("guess");
    const statuses: number[] = [];
    for (let i = 0; i < 12; i++) statuses.push((await (i % 2 ? a : b).call("POST", "/v1/auth/login", { body: { email, password: `wrong-guess-${i}` } })).status);
    expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true);
    expect(statuses.slice(10)).toEqual([429, 429]); // 10 per 5 minutes in total, not per server
  });
});

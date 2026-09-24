import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { backoff, enqueue, PermanentJobError, registerJobHandler } from "../src/platform/jobs.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let orgId = "";
const seen: string[] = [];
let flaky = 2;

registerJobHandler("test.echo", async (_deps, job) => {
  seen.push(String(job.payload.msg));
});
registerJobHandler("test.flaky", async () => {
  if (flaky-- > 0) throw new Error("upstream timed out");
});
registerJobHandler("test.broken", async () => {
  throw new PermanentJobError("bad configuration");
});

const enq = (kind: string, payload: Record<string, unknown> = {}, opts = {}) => h.deps.db.tenant(orgId, (tx) => enqueue(tx, orgId, kind, payload, opts));
const job = async (id: string) => (await owner.query("SELECT status, attempts, last_error, run_at FROM jobs WHERE id = $1", [id])).rows[0];
const makeDue = (id: string) => owner.query("UPDATE jobs SET run_at = now() WHERE id = $1", [id]);

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Jobs Inc", email: uniqueEmail("j"), password: PASSWORD, given_name: "J" } })).body.token;
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("background jobs", () => {
  it("runs enqueued jobs once", async () => {
    const id = (await enq("test.echo", { msg: "hello" }))!;
    expect(await h.jobs.runOnce({ orgId })).toBe(1);
    expect(seen).toEqual(["hello"]);
    expect(await job(id)).toMatchObject({ status: "done", attempts: 1 });
    expect(await h.jobs.runOnce({ orgId })).toBe(0);
  });

  it("deduplicates pending work by key", async () => {
    const a = await enq("test.echo", { msg: "a" }, { dedupeKey: "sync:1" });
    const b = await enq("test.echo", { msg: "b" }, { dedupeKey: "sync:1" });
    expect(a).not.toBeNull();
    expect(b).toBeNull();
    await h.jobs.runOnce({ orgId });
    expect(await enq("test.echo", { msg: "c" }, { dedupeKey: "sync:1" })).not.toBeNull(); // done jobs don't block new ones
    await h.jobs.runOnce({ orgId });
    expect(seen.slice(-2)).toEqual(["a", "c"]);
  });

  it("retries transient failures with backoff", async () => {
    const id = (await enq("test.flaky"))!;
    await h.jobs.runOnce({ orgId });
    let j = await job(id);
    expect(j).toMatchObject({ status: "queued", attempts: 1, last_error: "upstream timed out" });
    expect(new Date(j.run_at).getTime()).toBeGreaterThan(Date.now() + 20_000);
    await makeDue(id);
    await h.jobs.runOnce({ orgId });
    await makeDue(id);
    await h.jobs.runOnce({ orgId });
    j = await job(id);
    expect(j).toMatchObject({ status: "done", attempts: 3 });
    expect([backoff(1), backoff(2), backoff(20)]).toEqual([30_000, 60_000, 3_600_000]);
  });

  it("gives up on permanent errors and after max attempts", async () => {
    const broken = (await enq("test.broken"))!;
    await h.jobs.runOnce({ orgId });
    expect(await job(broken)).toMatchObject({ status: "dead", attempts: 1, last_error: "bad configuration" });
    flaky = 99;
    const capped = (await enq("test.flaky", {}, { maxAttempts: 2 }))!;
    await h.jobs.runOnce({ orgId });
    await makeDue(capped);
    await h.jobs.runOnce({ orgId });
    expect(await job(capped)).toMatchObject({ status: "dead", attempts: 2 });
  });

  it("re-runs jobs whose worker died mid-run", async () => {
    const id = (await enq("test.echo", { msg: "orphan" }))!;
    await owner.query("UPDATE jobs SET status = 'running', locked_until = now() - interval '1 second' WHERE id = $1", [id]);
    await h.jobs.runOnce({ orgId });
    expect(seen.at(-1)).toBe("orphan");
    expect(await job(id)).toMatchObject({ status: "done" });
  });

  it("keeps tenants apart", async () => {
    const other = (await h.call("POST", "/v1/signup", { body: { organization_name: "Other", email: uniqueEmail("o"), password: PASSWORD, given_name: "O" } })).body.token;
    const otherOrg = (await h.call("GET", "/v1/me", { token: other })).body.organization.id;
    const visible = await h.deps.db.tenant(otherOrg, (tx) => tx.selectFrom("jobs").select("id").execute());
    expect(visible).toEqual([]);
  });
});

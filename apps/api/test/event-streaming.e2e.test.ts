import { createHmac, randomUUID } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { deliver } from "../src/integrations/stream.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Webhooks and SIEM streaming (INT-03, AUD-04): signed, filtered, ordered, gapless, resilient. */

type Received = { path: string; headers: http.IncomingHttpHeaders; body: string };
const received: Received[] = [];
const failures: Record<string, number[]> = {}; // path → status codes to answer next
let server: http.Server;
let base = "";

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** Delivery waits for older transactions anywhere in the cluster (other test files) to finish: poll. */
async function deliverUntil(id: string, done: () => boolean, tries = 40) {
  for (let i = 0; i < tries; i++) {
    await owner.query("UPDATE event_destinations SET next_attempt_at = now() WHERE id = $1", [id]);
    await deliver(h.deps, orgId, id);
    if (done()) return;
    await sleep(100);
  }
  throw new Error("delivery didn't happen");
}
const at = (path: string) => received.filter((r) => r.path === path);
const dests = async () => (await h.call("GET", "/v1/event-destinations", { token: admin })).body.data as Record<string, any>[];
const create = (body: Record<string, unknown>) => h.call("POST", "/v1/event-destinations", { token: admin, body });
const newUser = async (tag: string) => (await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail(tag), given_name: tag } })).body;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c)).on("end", () => {
      const status = failures[req.url!]?.shift();
      if (status) return res.writeHead(status).end("upstream unavailable");
      received.push({ path: req.url!, headers: req.headers, body });
      res.writeHead(200).end("ok");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Globex", email: uniqueEmail("hank"), password: PASSWORD, given_name: "Hank" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
});
afterAll(async () => {
  server.close();
  await owner.end();
  await h.close();
});

describe("webhooks", () => {
  let id = "";
  let secret = "";

  it("are created with a signing secret shown once, and only for new events", async () => {
    await newUser("before"); // happened before the webhook existed: not delivered
    expect((await create({ kind: "webhook", name: "x", url: "ftp://example.com" })).body.code).toBe("unsafe_url");
    const r = await create({ kind: "webhook", name: "HR system", url: `${base}/hook`, event_filter: ["user."] });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    secret = r.body.signing_secret;
    expect(secret).toMatch(/^whsec_/);
    id = r.body.data[0].id;
    expect(r.body.data[0]).toMatchObject({ kind: "webhook", status: "waiting", backlog: 0 });
    expect(JSON.stringify(await dests())).not.toContain(secret);
  });

  it("deliver matching events, signed", async () => {
    const u = await newUser("ann");
    await h.call("POST", "/v1/groups", { token: admin, body: { name: "Not for the webhook" } }); // filtered out
    await deliverUntil(id, () => at("/hook").length >= 1);
    expect(at("/hook")).toHaveLength(1);
    const { headers, body } = at("/hook")[0]!;
    const event = JSON.parse(body);
    expect(event).toMatchObject({ type: "user.created", target: { id: u.id }, actor: { type: "user" } });
    expect(headers["nexus-event-type"]).toBe("user.created");
    expect(headers["nexus-event-id"]).toBe(event.id);
    // Verify like a receiver would: HMAC over "<t>.<raw body>".
    const [, t, v1] = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(String(headers["nexus-signature"]))!;
    expect(v1).toBe(createHmac("sha256", secret).update(`${t}.${body}`).digest("hex"));
    expect(Math.abs(Date.now() / 1000 - Number(t))).toBeLessThan(60);
    const d = (await dests())[0]!;
    expect(d).toMatchObject({ status: "healthy", backlog: 0 });
  });

  it("resume after an outage without losing or repeating events", async () => {
    received.length = 0;
    const a = await newUser("one");
    const b = await newUser("two");
    const c = await newUser("three");
    // The receiver takes the first event, then breaks.
    let calls = 0;
    const orig = server.listeners("request")[0] as (req: http.IncomingMessage, res: http.ServerResponse) => void;
    server.removeAllListeners("request");
    server.on("request", (req, res) => {
      calls++;
      if (calls === 2) {
        req.resume();
        return res.writeHead(503).end("down");
      }
      orig(req, res);
    });
    await deliverUntil(id, () => calls >= 2);
    server.removeAllListeners("request");
    server.on("request", orig);
    expect(at("/hook").map((r) => JSON.parse(r.body).target.id)).toEqual([a.id]);
    const failing = (await dests())[0]!;
    expect(failing).toMatchObject({ status: "failing", consecutive_failures: 1, backlog: 2 });
    expect(failing.last_error).toContain("HTTP 503");

    await deliverUntil(id, () => at("/hook").length >= 3);
    expect(at("/hook").map((r) => JSON.parse(r.body).target.id)).toEqual([a.id, b.id, c.id]); // in order, once each
    expect((await dests())[0]).toMatchObject({ status: "healthy", consecutive_failures: 0 });
    const log = (await h.call("GET", `/v1/event-destinations/${id}/deliveries`, { token: admin })).body.data;
    expect(log.slice(0, 2).map((x: { ok: boolean }) => x.ok)).toEqual([true, false]);
  });

  it("never skip an event committed late by a slow transaction", async () => {
    received.length = 0;
    // A slow transaction writes an audit event first and commits last.
    const slow = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
    await slow.connect();
    await slow.query("BEGIN");
    await slow.query("INSERT INTO audit_events (id, org_id, type, actor_type) VALUES ($1, $2, 'user.slow_import', 'system')", [randomUUID(), orgId]);
    const fast = await newUser("fast"); // commits while the slow one is still open
    await sleep(300);
    await deliver(h.deps, orgId, id);
    expect(at("/hook")).toHaveLength(0); // held back, not skipped past
    await slow.query("COMMIT");
    await slow.end();
    await deliverUntil(id, () => at("/hook").length >= 2);
    expect(at("/hook").map((r) => JSON.parse(r.body).type)).toEqual(["user.slow_import", "user.created"]);
    expect(JSON.parse(at("/hook")[1]!.body).target.id).toBe(fast.id);
  });

  it("alert after repeated failures, and turn off at the limit", async () => {
    await owner.query("UPDATE event_destinations SET consecutive_failures = 4 WHERE id = $1", [id]);
    failures["/hook"] = [500];
    await newUser("four");
    await deliverUntil(id, () => (failures["/hook"]?.length ?? 0) === 0);
    let inbox = (await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin })).body.data;
    expect(inbox[0]).toMatchObject({ title: "Can't deliver events to HR system", severity: "warning" });

    await owner.query("UPDATE event_destinations SET consecutive_failures = 99 WHERE id = $1", [id]);
    failures["/hook"] = [500];
    await deliverUntil(id, () => (failures["/hook"]?.length ?? 0) === 0);
    const off = (await dests())[0]!;
    expect(off).toMatchObject({ enabled: false, status: "off" });
    expect(off.disabled_reason).toContain("Turned off after 100 failed deliveries");
    inbox = (await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin })).body.data;
    expect(inbox[0]).toMatchObject({ title: "HR system was turned off", severity: "critical" });

    // Back on: resumes where it stopped.
    received.length = 0;
    await h.call("PATCH", `/v1/event-destinations/${id}`, { token: admin, body: { enabled: true } });
    await deliverUntil(id, () => at("/hook").length >= 1);
    expect(JSON.parse(at("/hook")[0]!.body).target.display).toContain("four");
  });
});

describe("SIEM streaming", () => {
  it("sends OCSF to Splunk HEC in batches", async () => {
    expect((await create({ kind: "splunk_hec", name: "Splunk", url: `${base}/splunk` })).body.code).toBe("secret_required");
    const r = await create({ kind: "splunk_hec", name: "Splunk", url: `${base}/splunk`, secret: "hec-token", format: "ocsf", config: { index: "security", sourcetype: "nexus:ocsf" }, start: "last_24h" });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.signing_secret).toBeNull();
    const id = r.body.data.find((d: { name: string }) => d.name === "Splunk").id;
    await deliverUntil(id, () => at("/splunk").length >= 1);
    const req = at("/splunk")[0]!;
    expect(req.headers.authorization).toBe("Splunk hec-token");
    const lines = req.body.split("\n").map((l) => JSON.parse(l));
    expect(lines.length).toBeGreaterThan(5); // the day's backlog, in one request
    expect(lines[0]).toMatchObject({ index: "security", sourcetype: "nexus:ocsf", source: "votal-nexus" });
    const signup = lines.find((l) => l.event.metadata.event_code === "user.created");
    expect(signup.event).toMatchObject({ class_uid: 3001, activity_id: 1, metadata: { product: { name: "Votal Nexus" }, tenant_uid: orgId } });
  });

  it("sends to Datadog Logs", async () => {
    const r = await create({ kind: "datadog", name: "Datadog", url: `${base}/dd`, secret: "dd-key", config: { tags: "env:prod,team:secops" } });
    const id = r.body.data.find((d: { name: string }) => d.name === "Datadog").id;
    const test = await h.call("POST", `/v1/event-destinations/${id}/test`, { token: admin, body: {} });
    expect(test.body).toEqual({ ok: true, http_status: 200, error: "" });
    await newUser("dd");
    await deliverUntil(id, () => at("/dd").length >= 2);
    const req = at("/dd")[1]!;
    expect(req.headers["dd-api-key"]).toBe("dd-key");
    const logs = JSON.parse(req.body);
    expect(logs[0]).toMatchObject({ ddsource: "votal-nexus", service: "nexus", ddtags: "env:prod,team:secops", event_type: "user.created" });
    expect(JSON.parse(logs[0].message)).toMatchObject({ type: "user.created" });
  });

  it("only admins manage streams, and API keys can't be granted it", async () => {
    const email = uniqueEmail("sec");
    await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Sec", password: PASSWORD, roles: ["security_analyst"] } });
    const analyst = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    expect((await h.call("GET", "/v1/event-destinations", { token: analyst })).status).toBe(403);
    expect((await h.call("POST", "/v1/api-keys", { token: admin, body: { name: "siem", scopes: ["integrations:manage"] } })).status).toBe(400);
  });
});

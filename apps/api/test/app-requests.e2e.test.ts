import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { enqueue } from "../src/platform/jobs.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Asking for a blocked app, or for software, through access requests; approved by a manager. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let orgId = "";
const people: Record<string, { id: string; token: string; email: string }> = {};
const devices: Record<string, { d: SoftDevice; id: string }> = {};
let ruleId = "";
let pkgId = "";
const catalog: Record<string, string> = {};

const posture = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
async function checkin(name: string, extra: Record<string, unknown> = {}) {
  const body = JSON.stringify({ device: { agent_version: "0.2.0" }, posture, ...extra });
  const res = await h.app.request("/v1/agent/checkin", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await devices[name]!.d.proof("/v1/agent/checkin", body)}` }, body });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, any>;
}
const policy = async (name: string) => JSON.parse(Buffer.from((await checkin(name)).enforcement.split(".")[1], "base64url").toString());
const stopped = (at = new Date()) => ({ enforcement: { events: [{ rule_id: ruleId, action: "terminated", subject: "/usr/games/chess", user: "alice", count: 1, at: at.toISOString() }] } });
const notes = async (who: string, category: string) => (await h.call("GET", "/v1/me/notifications?limit=50&filter=all", { token: people[who]!.token })).body.data.filter((n: any) => n.category === category);

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  const rootEmail = uniqueEmail("root");
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Requests Co", email: rootEmail, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token: admin })).body;
  orgId = me.organization.id;
  people.root = { id: me.user.id, token: admin, email: rootEmail };
  for (const n of ["mia", "alice", "bob"]) {
    const email = uniqueEmail(n);
    const id = (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: n, password: PASSWORD } })).body.id;
    people[n] = { id, email, token: (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token };
  }
  await h.call("PATCH", `/v1/users/${people.alice!.id}`, { token: admin, body: { manager_id: people.mia!.id } }); // Mia manages Alice
  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "t" } })).body.token;
  for (const [name, owner] of [["alice-pc", "alice"], ["bob-pc", "bob"]] as const) {
    const d = await new SoftDevice().init();
    const body = JSON.stringify({ token: t, device: { hostname: name, platform: "linux", os_version: "24.04", agent_version: "0.2.0" } });
    const res = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof("/v1/agent/enroll", body, { enroll: true })}` }, body });
    d.id = ((await res.json()) as any).device_id;
    devices[name] = { d, id: d.id };
    await db.query("UPDATE devices SET primary_user_id = $1 WHERE id = $2", [people[owner]!.id, d.id]);
  }
  ruleId = (await h.call("POST", "/v1/enforcement/rules", { token: admin, body: { name: "Chess", kind: "app", match: "name", value: "chess", mode: "block", target: { all: true }, platforms: ["macos", "windows", "linux"], reason: "Not for work" } })).body.id;
  pkgId = (await h.call("POST", "/v1/software-packages", { token: admin, body: { name: "htop", kind: "apt", ref: "htop" } })).body.id;
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("requests for apps on devices", () => {
  it("makes a block rule and a package requestable (domain rules can't be)", async () => {
    const domain = (await h.call("POST", "/v1/enforcement/rules", { token: admin, body: { name: "Chat", kind: "domain", match: "domain", value: "chat.example.com", mode: "block", target: { all: true }, platforms: ["linux"], reason: "x" } })).body.id;
    expect((await h.call("POST", "/v1/access/catalog", { token: admin, body: { resource_type: "block_exception", resource_id: domain, stages: [{ kind: "manager" }] } })).body.code).toBe("domain_rule");
    const a = await h.call("POST", "/v1/access/catalog", { token: admin, body: { resource_type: "block_exception", resource_id: ruleId, max_hours: 8, stages: [{ kind: "manager" }] } });
    expect(a.status, JSON.stringify(a.body)).toBe(201);
    catalog.chess = a.body.data.find((x: any) => x.resource_type === "block_exception").id;
    const b = await h.call("POST", "/v1/access/catalog", { token: admin, body: { resource_type: "software", resource_id: pkgId, allow_permanent: true, stages: [{ kind: "manager" }] } });
    catalog.htop = b.body.data.find((x: any) => x.resource_type === "software").id;
    const seen = (await h.call("GET", "/v1/access/catalog", { token: people.alice!.token })).body.data.map((x: any) => x.name).sort();
    expect(seen).toEqual(["Chess", "htop"]); // the thing's own name; the card says it's a blocked app or software
  });

  it("tells the device's user when an app is stopped, once a day, with a way to ask for it", async () => {
    expect((await policy("alice-pc")).rules.map((r: any) => r.id)).toContain(ruleId);
    await checkin("alice-pc", stopped());
    await checkin("alice-pc", stopped()); // relaunched: no second notification
    const n = await notes("alice", "device.app_blocked");
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ title: "chess was stopped on alice-pc", link: `/access-requests?request=${catalog.chess}` });
    expect(await notes("bob", "device.app_blocked")).toHaveLength(0);
  });

  it("an approved exception unblocks the app on the requester's devices only, until it expires", async () => {
    const r = await h.call("POST", "/v1/access/requests", { token: people.alice!.token, body: { catalog_id: catalog.chess, justification: "Chess club demo for a customer", duration_hours: 2 } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const approvals = (await h.call("GET", "/v1/access/requests?view=approvals", { token: people.mia!.token })).body.data;
    expect(approvals.map((x: any) => x.resource.name)).toEqual(["Chess"]);
    expect((await notes("mia", "access.approval"))[0].title).toMatch(/asks to use Chess, which is blocked$/);
    expect((await h.call("POST", `/v1/access/requests/${r.body.id}/decision`, { token: people.mia!.token, body: { decision: "approve", comment: "ok" } })).status).toBe(200);

    expect((await policy("alice-pc")).rules.map((x: any) => x.id)).not.toContain(ruleId);
    expect((await policy("bob-pc")).rules.map((x: any) => x.id)).toContain(ruleId);
    // Time's up: the rule is back.
    await db.query("UPDATE access_requests SET expires_at = now() - interval '1 minute' WHERE id = $1", [r.body.id]);
    await h.deps.db.tenant(orgId, (tx) => enqueue(tx, orgId, "access.expire", { request_id: r.body.id }));
    await h.jobs.runOnce({ orgId });
    expect((await db.query("SELECT status FROM access_requests WHERE id = $1", [r.body.id])).rows[0].status).toBe("ended");
    expect((await policy("alice-pc")).rules.map((x: any) => x.id)).toContain(ruleId);
  });

  it("an approved software request installs it on the requester's devices", async () => {
    const r = await h.call("POST", "/v1/access/requests", { token: people.alice!.token, body: { catalog_id: catalog.htop, justification: "Need it to debug the build server", duration_hours: null } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect((await policy("alice-pc")).software).toEqual([]);
    await h.call("POST", `/v1/access/requests/${r.body.id}/decision`, { token: people.mia!.token, body: { decision: "approve" } });
    expect((await policy("alice-pc")).software).toEqual([{ id: pkgId, name: "htop", action: "install", kind: "apt", ref: "htop" }]);
    expect((await policy("bob-pc")).software).toEqual([]);
    const pkg = (await h.call("GET", "/v1/software-packages", { token: admin })).body.data.find((p: any) => p.id === pkgId);
    expect(pkg.assignments).toEqual([expect.objectContaining({ user_email: people.alice!.email, action: "install" })]);
    expect((await h.call("GET", "/v1/access/catalog", { token: people.alice!.token })).body.data.find((x: any) => x.id === catalog.htop).you.has_access).toBe(true);
    // Giving it back stops keeping it there.
    await h.call("POST", `/v1/access/requests/${r.body.id}/revoke`, { token: people.alice!.token, body: { reason: "Done" } });
    expect((await policy("alice-pc")).software).toEqual([]);
  });
});

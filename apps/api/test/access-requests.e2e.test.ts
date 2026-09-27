import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { enqueue } from "../src/platform/jobs.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Access requests, approvals and automatic expiry (JIT-01/02/04), and just-in-time admin (OPS-11). */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let orgId = "";
const people: Record<string, { id: string; token: string; email: string }> = {};
let appId = "";
let appOwners = "";
let appEntry = "";
let adminEntry = "";

async function person(name: string, roles: string[] = []) {
  const email = uniqueEmail(name);
  const id = (await h.call("POST", "/v1/users", { token: people.root!.token, body: { email, given_name: name, password: PASSWORD, roles } })).body.id;
  const token = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
  people[name] = { id, token, email };
}
const as = (name: string) => people[name]!.token;
const request = (who: string, body: Record<string, unknown>) => h.call("POST", "/v1/access/requests", { token: as(who), body });
const decide = (who: string, id: string, decision: "approve" | "deny", comment = "") => h.call("POST", `/v1/access/requests/${id}/decision`, { token: as(who), body: { decision, comment } });
const inbox = async (who: string) => (await h.call("GET", "/v1/me/notifications?limit=10&filter=all", { token: as(who) })).body.data as { title: string; category: string }[];
const hasApp = async (who: string) => ((await h.call("GET", "/v1/me/apps", { token: as(who) })).body.data as { id: string }[]).some((a) => a.id === appId);

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("root");
  const token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Govern Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token })).body;
  orgId = me.organization.id;
  people.root = { id: me.user.id, token, email };
  for (const n of ["alice", "bob", "carol", "dave"]) await person(n);
  await h.call("PATCH", `/v1/users/${people.alice!.id}`, { token, body: { manager_id: people.bob!.id } });
  appId = (await h.call("POST", "/v1/apps", { token, body: { protocol: "oidc", name: "Salesforce", redirect_uris: ["https://sf.example.com/cb"] } })).body.app.id;
  appOwners = (await h.call("POST", "/v1/groups", { token, body: { name: "Salesforce owners" } })).body.id;
  await h.call("POST", `/v1/groups/${appOwners}/members`, { token, body: { user_ids: [people.carol!.id] } });
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("the catalog", () => {
  it("is managed by access admins", async () => {
    expect((await h.call("POST", "/v1/access/catalog", { token: as("alice"), body: { resource_type: "app", resource_id: appId } })).status).toBe(403);
    const bad = await h.call("POST", "/v1/access/catalog", { token: as("root"), body: { resource_type: "role", role: "admin", allow_permanent: true } });
    expect(bad.body.code).toBe("role_permanent");
    expect((await h.call("POST", "/v1/access/catalog", { token: as("root"), body: { resource_type: "role", role: "owner" } })).status).toBe(400); // never owner
    const app = await h.call("POST", "/v1/access/catalog", {
      token: as("root"),
      body: { resource_type: "app", resource_id: appId, description: "CRM", max_hours: 72, stages: [{ kind: "manager" }, { kind: "group", id: appOwners }] },
    });
    expect(app.status, JSON.stringify(app.body)).toBe(201);
    appEntry = app.body.data[0].id;
    const role = await h.call("POST", "/v1/access/catalog", {
      token: as("root"),
      body: { resource_type: "role", role: "admin", max_hours: 4, stages: [{ kind: "role", role: "owner" }], eligible: { users: [people.dave!.id], groups: [] } },
    });
    adminEntry = role.body.data.find((x: any) => x.resource_type === "role").id;
    expect((await h.call("POST", "/v1/access/catalog", { token: as("root"), body: { resource_type: "app", resource_id: appId } })).body.code).toBe("already_requestable");
  });

  it("shows people what they can ask for", async () => {
    const list = (await h.call("GET", "/v1/access/catalog", { token: as("dave") })).body.data;
    expect(list.map((x: any) => x.name).sort()).toEqual(["Salesforce", "admin role"]);
    expect(list.find((x: any) => x.resource_type === "role").you).toEqual({ eligible: true, has_access: false, open_request: null });
  });
});

describe("a request with two approval stages", () => {
  let reqId = "";

  it("goes to the manager first, then the app owners, then grants", async () => {
    const r = await request("alice", { catalog_id: appEntry, justification: "Q3 pipeline review", duration_hours: 24 });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    reqId = r.body.id;
    expect(r.body).toMatchObject({ status: "pending", stage: 0, stages: 2, approvers: [people.bob!.email] });
    expect((await inbox("bob"))[0]!.title).toBe(`${people.alice!.email} requests Salesforce`);
    // Not carol's turn yet; never alice's own.
    expect((await decide("carol", reqId, "approve")).body.code).toBe("not_an_approver");
    expect((await decide("alice", reqId, "approve")).status).toBe(403);
    expect((await h.call("GET", "/v1/access/requests?view=approvals", { token: as("carol") })).body.data).toEqual([]);

    expect((await decide("bob", reqId, "approve", "Fine by me")).body).toMatchObject({ status: "pending", stage: 1, approvers: [people.carol!.email] });
    expect((await h.call("GET", "/v1/access/requests?view=approvals", { token: as("carol") })).body.data[0].id).toBe(reqId);
    const done = await decide("carol", reqId, "approve");
    expect(done.body).toMatchObject({ status: "active", decisions: [{ approver: people.bob!.email, comment: "Fine by me" }, { approver: people.carol!.email }] });
    const left = new Date(done.body.expires_at).getTime() - Date.now();
    expect(left).toBeGreaterThan(23.9 * 3600_000);
    expect(await hasApp("alice")).toBe(true);
    expect((await inbox("alice"))[0]!.title).toMatch(/^You have Salesforce until /);
  });

  it("leaves a linked trail in the audit log", async () => {
    const ev = (await h.call("GET", "/v1/audit/events?limit=20", { token: as("root") })).body.data.filter((e: any) => e.details?.request_id === reqId).map((e: any) => e.type);
    expect(ev.reverse()).toEqual(["access.requested", "access.approved", "access.approved", "access.granted"]);
  });

  it("can't be requested again while granted", async () => {
    expect((await request("alice", { catalog_id: appEntry, justification: "again please", duration_hours: 1 })).body.code).toBe("already_has_access");
  });

  it("ends by itself when the time is up", async () => {
    await owner.query("UPDATE access_requests SET expires_at = now() - interval '1 minute' WHERE id = $1", [reqId]);
    expect((await owner.query("SELECT request_id FROM nexus_access_grants_expired()")).rows.map((r) => r.request_id)).toContain(reqId);
    await h.deps.db.tenant(orgId, (tx) => enqueue(tx, orgId, "access.expire", { request_id: reqId }));
    await h.jobs.runOnce({ orgId });
    const r = (await h.call("GET", "/v1/access/requests", { token: as("alice") })).body.data.find((x: any) => x.id === reqId);
    expect(r).toMatchObject({ status: "ended", end_reason: "Granted for 24 h; the time is up" });
    expect(await hasApp("alice")).toBe(false);
    expect((await inbox("alice"))[0]!.title).toBe("Your access to Salesforce ended");
    const ev = (await h.call("GET", "/v1/audit/events?type=access.expired", { token: as("root") })).body.data[0];
    expect(ev.details).toMatchObject({ request_id: reqId });
  });

  it("can be denied, withdrawn, and given back early", async () => {
    const r1 = (await request("alice", { catalog_id: appEntry, justification: "one more look", duration_hours: 2 })).body;
    expect((await decide("bob", r1.id, "deny", "Use the dashboard instead")).body).toMatchObject({ status: "denied", end_reason: "Use the dashboard instead" });
    expect((await inbox("alice"))[0]!.title).toBe(`${people.bob!.email} denied your request for Salesforce`);
    const r2 = (await request("alice", { catalog_id: appEntry, justification: "changed my mind", duration_hours: 2 })).body;
    expect((await h.call("POST", `/v1/access/requests/${r2.id}/cancel`, { token: as("alice"), body: {} })).body.status).toBe("canceled");
    expect((await request("alice", { catalog_id: appEntry, justification: "no end please", duration_hours: null })).body.code).toBe("duration_required");
    expect((await request("alice", { catalog_id: appEntry, justification: "too long", duration_hours: 100 })).body.code).toBe("too_long");
  });
});

describe("just-in-time admin", () => {
  it("lets eligible people activate a role themselves, and it works at once", async () => {
    expect((await h.call("GET", "/v1/access/catalog?all=true", { token: as("dave") })).body.data.every((x: any) => x.enabled)).toBe(true); // not admin: all=true ignored
    const r = await request("dave", { catalog_id: adminEntry, justification: "Fix the broken SSO app for sales", duration_hours: 2 });
    expect(r.body).toMatchObject({ status: "active", auto_approved: true });
    expect((await h.call("POST", "/v1/groups", { token: as("dave"), body: { name: "made by dave" } })).status).toBe(201); // admin now
    const ev = (await h.call("GET", "/v1/audit/events?type=access.granted", { token: as("root") })).body.data[0];
    expect(ev.details.why).toMatch(/^Pre-approved; activated by /);
    // Revoked: gone on the very next request.
    await h.call("POST", `/v1/access/requests/${r.body.id}/revoke`, { token: as("root"), body: { reason: "Done with the fix" } });
    expect((await h.call("POST", "/v1/groups", { token: as("dave"), body: { name: "too late" } })).status).toBe(403);
  });

  it("needs an owner's approval for everyone else, within the time limit", async () => {
    expect((await request("alice", { catalog_id: adminEntry, justification: "rotate keys", duration_hours: 8 })).body.code).toBe("too_long");
    const r = (await request("alice", { catalog_id: adminEntry, justification: "rotate keys", duration_hours: 3 })).body;
    expect(r).toMatchObject({ status: "pending", approvers: [people.root!.email] });
    expect((await inbox("root")).find((n) => n.category === "access.approval")!.title).toBe(`${people.alice!.email} requests admin role`);
    expect((await decide("root", r.id, "approve")).body.status).toBe("active");
    expect((await h.call("GET", "/v1/me", { token: as("alice") })).body.roles).toContain("admin");
    // Giving it back early.
    expect((await h.call("POST", `/v1/access/requests/${r.id}/revoke`, { token: as("alice"), body: {} })).body).toMatchObject({ status: "revoked", end_reason: "Given back early" });
  });
});

describe("approvers", () => {
  it("fall back to admins when a stage has nobody, and never include the requester", async () => {
    // Carol has no manager: the manager stage falls back to owners and admins.
    const r = (await request("carol", { catalog_id: appEntry, justification: "for a customer call", duration_hours: 1 })).body;
    expect(r.approvers).toEqual([people.root!.email]);
    // The only possible approver asking: nobody else can approve.
    await h.call("PATCH", `/v1/access/catalog/${appEntry}`, { token: as("root"), body: { stages: [{ kind: "users", ids: [people.root!.id] }] } });
    expect((await request("root", { catalog_id: appEntry, justification: "for myself", duration_hours: 1 })).body.code).toBe("no_approver");
  });

  it("need a valid manager", async () => {
    expect((await h.call("PATCH", `/v1/users/${people.bob!.id}`, { token: as("root"), body: { manager_id: people.alice!.id } })).body.code).toBe("invalid_manager"); // loop
    expect((await h.call("PATCH", `/v1/users/${people.bob!.id}`, { token: as("root"), body: { manager_id: people.bob!.id } })).body.code).toBe("invalid_manager");
    expect((await h.call("GET", `/v1/users/${people.alice!.id}`, { token: as("root") })).body.manager_id).toBe(people.bob!.id);
  });

  it("stay inside the organization", async () => {
    const other = (await h.call("POST", "/v1/signup", { body: { organization_name: "Else", email: uniqueEmail("x"), password: PASSWORD, given_name: "X" } })).body.token;
    await h.call("PATCH", "/v1/org/settings", { token: other, body: { mfa_policy: "off" } });
    expect((await h.call("GET", "/v1/access/requests?view=all", { token: other })).body.data).toEqual([]);
    expect((await h.call("POST", "/v1/access/requests", { token: other, body: { catalog_id: appEntry, justification: "sneaky", duration_hours: 1 } })).status).toBe(404);
  });
});

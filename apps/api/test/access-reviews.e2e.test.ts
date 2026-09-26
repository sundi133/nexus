import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { enqueue } from "../src/platform/jobs.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Access reviews (JIT-05): snapshot, reviewers, decisions, applying them, evidence. */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let orgId = "";
const P: Record<string, { id: string; token: string; email: string }> = {};
let appId = "";
let sales = "";

async function person(name: string, extra: Record<string, unknown> = {}) {
  const email = uniqueEmail(name);
  const id = (await h.call("POST", "/v1/users", { token: P.root!.token, body: { email, given_name: name, password: PASSWORD, ...extra } })).body.id;
  const token = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
  P[name] = { id, token, email };
}
const as = (n: string) => P[n]!.token;
const review = (id: string, who = "root") => h.call("GET", `/v1/access-reviews/${id}`, { token: as(who) });
const decide = (id: string, who: string, items: { id: string; decision: "keep" | "revoke"; note?: string }[]) => h.call("POST", `/v1/access-reviews/${id}/decisions`, { token: as(who), body: { items } });
const assigned = async (userId: string) => (await h.call("GET", `/v1/apps/${appId}/assignments`, { token: as("root") })).body.data.some((a: any) => a.principal_id === userId);

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("root");
  const token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Review Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token })).body;
  orgId = me.organization.id;
  P.root = { id: me.user.id, token, email };
  await person("bob");
  await person("alice");
  await person("carol", { given_name: "=HYPERLINK(\"http://evil\")" });
  await person("dave");
  await person("glass");
  await h.call("PATCH", `/v1/users/${P.alice!.id}`, { token, body: { manager_id: P.bob!.id } });
  appId = (await h.call("POST", "/v1/apps", { token, body: { protocol: "oidc", name: "Payroll", redirect_uris: ["https://payroll.example.com/cb"] } })).body.app.id;
  sales = (await h.call("POST", "/v1/groups", { token, body: { name: "Sales" } })).body.id;
  await h.call("POST", `/v1/groups/${sales}/members`, { token, body: { user_ids: [P.dave!.id] } });
  await h.call("POST", `/v1/apps/${appId}/assignments`, { token, body: { principals: [{ type: "user", id: P.alice!.id }, { type: "user", id: P.carol!.id }, { type: "user", id: P.glass!.id }, { type: "group", id: sales }] } });
  await owner.query("UPDATE users SET break_glass = true WHERE id = $1", [P.glass!.id]);
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("an app review with managers as reviewers", () => {
  let id = "";

  it("snapshots who has the app, and picks each person's reviewer", async () => {
    expect((await h.call("POST", "/v1/access-reviews", { token: as("alice"), body: { name: "x", scope: { type: "app", id: appId }, reviewers: { kind: "users", ids: [P.bob!.id] } } })).status).toBe(403);
    const r = await h.call("POST", "/v1/access-reviews", {
      token: as("root"),
      body: { name: "Q3 Payroll access", scope: { type: "app", id: appId }, reviewers: { kind: "manager", fallback_ids: [P.root!.id] }, due_in_days: 7, on_no_decision: "revoke" },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    id = r.body.id;
    expect(r.body).toMatchObject({ scope: { name: "Payroll" }, progress: { total: 3, decided: 0 } }); // break-glass left out
    const items = (await review(id)).body.items;
    const by = (n: string) => items.find((i: any) => i.user.id === P[n]!.id);
    expect(by("alice")).toMatchObject({ access: "assigned directly", reviewer: P.bob!.email });
    expect(by("carol")).toMatchObject({ reviewer: P.root!.email });
    expect(by("dave")).toMatchObject({ access: "via group Sales", reviewer: P.root!.email });
    expect((await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: as("bob") })).body.data[0].title).toBe("Review who has Payroll");
  });

  it("lets reviewers decide only their own items, never their own access", async () => {
    const mine = (await review(id, "bob")).body.items;
    expect(mine.map((i: any) => i.user.id)).toEqual([P.alice!.id]);
    const carolItem = (await review(id)).body.items.find((i: any) => i.user.id === P.carol!.id);
    expect((await decide(id, "bob", [{ id: carolItem.id, decision: "revoke" }])).status).toBe(403);
    expect((await decide(id, "alice", [{ id: mine[0].id, decision: "keep" }])).body.title).toBe("You can't review your own access");
    expect((await decide(id, "bob", [{ id: mine[0].id, decision: "revoke", note: "Moved to marketing" }])).body.review.progress).toMatchObject({ decided: 1, yours_to_decide: 0 });
    expect((await decide(id, "root", [{ id: carolItem.id, decision: "keep" }])).status).toBe(200);
  });

  it("applies the decisions when it closes, and the default to the rest", async () => {
    const r = await h.call("POST", `/v1/access-reviews/${id}/close`, { token: as("root"), body: {} });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.review).toMatchObject({ status: "closed", summary: { total: 3, kept: 1, revoked: 2, undecided: 1 } });
    expect(await assigned(P.alice!.id)).toBe(false);
    expect(await assigned(P.carol!.id)).toBe(true);
    const members = (await h.call("GET", `/v1/groups/${sales}/members`, { token: as("root") })).body.data.map((m: any) => m.id);
    expect(members).not.toContain(P.dave!.id); // via group: removed from the group
    expect((await decide(id, "root", [{ id: r.body.items[0].id, decision: "keep" }])).body.code).toBe("closed");
    const ev = (await h.call("GET", "/v1/audit/events?type=access.review_revoked", { token: as("root") })).body.data;
    expect(ev.every((e: any) => e.details.review_id === id)).toBe(true);
  });

  it("exports evidence, safe to open in a spreadsheet", async () => {
    const res = await h.app.request(`/v1/access-reviews/${id}/export`, { headers: { authorization: `Bearer ${as("root")}` } });
    expect(res.headers.get("content-type")).toContain("text/csv");
    const csv = await res.text();
    const lines = csv.trim().split("\r\n");
    expect(lines[0]).toBe('"review","scope","person","email","access","reviewer","decision","note","decided_by","decided_at","outcome","closed_at"');
    expect(lines).toHaveLength(4);
    expect(csv).toContain('"Moved to marketing"');
    expect(csv).toContain(`"'=HYPERLINK(""http://evil"")"`); // formula neutralised
  });
});

describe("admin role reviews", () => {
  it("never remove the last owner", async () => {
    const r = await h.call("POST", "/v1/access-reviews", { token: as("root"), body: { name: "Admins", scope: { type: "admin_roles" }, reviewers: { kind: "users", ids: [P.bob!.id] }, on_no_decision: "revoke" } });
    const items = (await review(r.body.id)).body.items;
    expect(items.map((i: any) => i.access)).toEqual(["owner role"]);
    const closed = await h.call("POST", `/v1/access-reviews/${r.body.id}/close`, { token: as("root"), body: {} });
    expect(closed.body.review.summary).toMatchObject({ skipped: 1, revoked: 0 });
    expect((await h.call("GET", "/v1/me", { token: as("root") })).body.roles).toContain("owner");
  });
});

describe("with access requests, and on a schedule", () => {
  it("ends a requested grant through its request, and closes at the due date", async () => {
    const cat = (await h.call("POST", "/v1/access/catalog", { token: as("root"), body: { resource_type: "app", resource_id: appId, stages: [] } })).body.data[0];
    const req = (await h.call("POST", "/v1/access/requests", { token: as("bob"), body: { catalog_id: cat.id, justification: "payroll run", duration_hours: 24 } })).body;
    expect(req.status).toBe("active");
    const r = (await h.call("POST", "/v1/access-reviews", { token: as("root"), body: { name: "Payroll again", scope: { type: "app", id: appId }, reviewers: { kind: "users", ids: [P.root!.id] }, due_in_days: 1, on_no_decision: "keep" } })).body;
    const bobItem = (await review(r.id)).body.items.find((i: any) => i.user.id === P.bob!.id);
    await decide(r.id, "root", [{ id: bobItem.id, decision: "revoke" }]);

    // A day before the due date: one reminder.
    const due = async () => (await owner.query("SELECT action FROM nexus_access_reviews_due() WHERE review_id = $1", [r.id])).rows.map((x) => x.action);
    expect(await due()).toEqual(["remind"]);
    await h.deps.db.tenant(orgId, (tx) => enqueue(tx, orgId, "access.review_remind", { review_id: r.id }));
    await h.jobs.runOnce({ orgId });
    expect(await due()).toEqual([]);
    // Due: it closes itself.
    await owner.query("UPDATE access_reviews SET due_at = now() - interval '1 minute' WHERE id = $1", [r.id]);
    expect(await due()).toEqual(["close"]);
    await h.deps.db.tenant(orgId, (tx) => enqueue(tx, orgId, "access.review_close", { review_id: r.id }));
    await h.jobs.runOnce({ orgId });
    expect((await review(r.id)).body.review.status).toBe("closed");
    const after = (await h.call("GET", "/v1/access/requests", { token: as("bob") })).body.data.find((x: any) => x.id === req.id);
    expect(after).toMatchObject({ status: "revoked", end_reason: "Revoked in an access review" });
    const closedEv = (await h.call("GET", "/v1/audit/events?type=access.review_closed", { token: as("root") })).body.data[0];
    expect(closedEv.actor.display).toBe("Access reviews (due date)");
  });
});

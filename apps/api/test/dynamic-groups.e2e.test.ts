import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Dynamic groups (DIR-05): rules, preview, automatic membership, protections. */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let orgId = "";
let token = "";
const U: Record<string, string> = {};
const domain = `dyn${Date.now()}.test`;

const create = async (name: string, extra: Record<string, unknown> = {}) =>
  (U[name] = (await h.call("POST", "/v1/users", { token, body: { email: `${name}@${domain}`, given_name: name, password: PASSWORD, ...extra } })).body.id);
const members = async (g: string) => ((await h.call("GET", `/v1/groups/${g}/members?limit=100`, { token })).body.data as { id: string }[]).map((m) => m.id).sort();
const settle = () => h.jobs.runOnce({ orgId });
const engineering = { match: "all", conditions: [{ attribute: "department", op: "equals", value: "engineering" }, { attribute: "email_domain", op: "equals", value: domain }] };

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("root");
  token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Dyn Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token })).body.organization.id;
  await create("ana", { department: "Engineering", title: "Staff Engineer" });
  await create("ben", { department: "engineering" });
  await create("cy", { department: "Sales" });
  await create("glass", { department: "Engineering" });
  await owner.query("UPDATE users SET break_glass = true WHERE id = $1", [U.glass]);
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("rules", () => {
  it("previews who a rule matches, case-insensitively, without break-glass accounts", async () => {
    const r = await h.call("POST", "/v1/groups/rule-preview", { token, body: { rule: engineering } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.count).toBe(2);
    expect(r.body.sample.map((s: any) => s.email).sort()).toEqual([`ana@${domain}`, `ben@${domain}`]);
  });

  it("supports any-of, in, contains and is_empty, and treats LIKE characters literally", async () => {
    const count = async (rule: unknown) => (await h.call("POST", "/v1/groups/rule-preview", { token, body: { rule } })).body.count;
    const inDomain = { attribute: "email_domain", op: "equals", value: domain };
    expect(await count({ match: "any", conditions: [{ attribute: "email", op: "equals", value: `cy@${domain}` }, { attribute: "email", op: "equals", value: `ana@${domain}` }] })).toBe(2);
    expect(await count({ match: "all", conditions: [inDomain, { attribute: "department", op: "in", values: ["Sales", "Marketing"] }] })).toBe(1);
    expect(await count({ match: "all", conditions: [inDomain, { attribute: "title", op: "contains", value: "engineer" }] })).toBe(1);
    expect(await count({ match: "all", conditions: [inDomain, { attribute: "title", op: "is_empty" }] })).toBe(2);
    expect(await count({ match: "all", conditions: [inDomain, { attribute: "department", op: "contains", value: "%" }] })).toBe(0);
    expect(await count({ match: "all", conditions: [inDomain, { attribute: "source", op: "equals", value: "none" }] })).toBe(3);
  });

  it("rejects incomplete conditions", async () => {
    const r = await h.call("POST", "/v1/groups/rule-preview", { token, body: { rule: { match: "all", conditions: [{ attribute: "department", op: "equals" }] } } });
    expect(r.status).toBe(400);
    expect((await h.call("POST", "/v1/groups/rule-preview", { token, body: { rule: { match: "all", conditions: [{ attribute: "password_hash", op: "is_not_empty" }] } } })).status).toBe(400);
  });
});

describe("a dynamic group", () => {
  let g = "";
  it("gets its members when created", async () => {
    const r = await h.call("POST", "/v1/groups", { token, body: { name: "Engineering", rule: engineering } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    g = r.body.id;
    expect(r.body).toMatchObject({ member_count: 2, rule: engineering });
    expect(r.body.rule_evaluated_at).toBeTruthy();
    expect(await members(g)).toEqual([U.ana, U.ben].sort());
  });

  it("follows people's changes, and new people", async () => {
    await h.call("PATCH", `/v1/users/${U.cy}`, { token, body: { department: "Engineering" } });
    await h.call("PATCH", `/v1/users/${U.ben}`, { token, body: { department: "Product" } });
    await create("dee", { department: "engineering" });
    await settle();
    expect(await members(g)).toEqual([U.ana, U.cy, U.dee].sort());
    const ev = (await h.call("GET", "/v1/audit/events?type=group.dynamic_updated", { token })).body.data;
    expect(ev[0].actor.display).toBe("Dynamic group rule");
  });

  it("drops people when they're deprovisioned", async () => {
    await h.call("POST", `/v1/users/${U.dee}/offboard`, { token, body: { reason: "left" } });
    await settle();
    expect(await members(g)).not.toContain(U.dee);
  });

  it("refuses manual member changes", async () => {
    expect((await h.call("POST", `/v1/groups/${g}/members`, { token, body: { user_ids: [U.ben] } })).body.code).toBe("dynamic_group");
    expect((await h.call("DELETE", `/v1/groups/${g}/members/${U.ana}`, { token })).body.code).toBe("dynamic_group");
  });

  it("previews a rule change against the group, then applies it", async () => {
    const rule = { match: "all", conditions: [{ attribute: "email_domain", op: "equals", value: domain }] };
    const pv = (await h.call("POST", "/v1/groups/rule-preview", { token, body: { rule, group_id: g } })).body;
    expect(pv).toMatchObject({ count: 3, adds: 1, removes: 0 }); // ana, ben, cy (not dee or glass)
    const r = await h.call("PATCH", `/v1/groups/${g}`, { token, body: { rule } });
    expect(r.body.member_count).toBe(3);
  });

  it("keeps its members, managed by hand, when the rule is removed", async () => {
    const r = await h.call("PATCH", `/v1/groups/${g}`, { token, body: { rule: null } });
    expect(r.body).toMatchObject({ rule: null, member_count: 3 });
    expect((await h.call("DELETE", `/v1/groups/${g}/members/${U.ana}`, { token })).status).toBe(204);
  });

  it("can't be requested in the access catalog", async () => {
    const d = (await h.call("POST", "/v1/groups", { token, body: { name: "Sales dyn", rule: { match: "all", conditions: [{ attribute: "department", op: "equals", value: "sales" }] } } })).body.id;
    const r = await h.call("POST", "/v1/access/catalog", { token, body: { resource_type: "group", resource_id: d, stages: [] } });
    expect(r.body.code).toBe("dynamic_group");
    // …and a requestable group can't become dynamic.
    const s = (await h.call("POST", "/v1/groups", { token, body: { name: "Static" } })).body.id;
    await h.call("POST", "/v1/access/catalog", { token, body: { resource_type: "group", resource_id: s, stages: [] } });
    expect((await h.call("PATCH", `/v1/groups/${s}`, { token, body: { rule: engineering } })).body.code).toBe("requestable");
  });

  it("doesn't reset the rule on unrelated edits", async () => {
    const d = (await h.call("POST", "/v1/groups", { token, body: { name: "Eng 2", rule: engineering } })).body.id;
    const r = await h.call("PATCH", `/v1/groups/${d}`, { token, body: { description: "renamed" } });
    expect(r.body.rule).toEqual(engineering);
  });

  it("isn't changed by access reviews: its rule decides", async () => {
    const d = (await h.call("POST", "/v1/groups", { token, body: { name: "Eng 3", rule: engineering } })).body.id;
    const me = (await h.call("GET", "/v1/me", { token })).body.user.id;
    const r = (await h.call("POST", "/v1/access-reviews", { token, body: { name: "Eng", scope: { type: "group", id: d }, reviewers: { kind: "users", ids: [me] }, on_no_decision: "revoke" } })).body;
    const closed = await h.call("POST", `/v1/access-reviews/${r.id}/close`, { token, body: {} });
    expect(closed.body.review.summary).toMatchObject({ revoked: 0, skipped: r.progress.total });
    expect((await members(d)).length).toBe(r.progress.total);
  });
});

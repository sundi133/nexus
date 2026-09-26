import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FakeScim, TOKEN } from "./fake-scim.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/**
 * Outbound SCIM provisioning (SCIM-01/02) against a strict fake SCIM 2.0
 * service: bearer auth, 409 on duplicate userName, filter search, PATCH
 * replace, and failures on demand.
 */

const fake = new FakeScim();
const scim = fake.state;
let base = "";
let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";
let appId = "";
let groupId = "";
const people: Record<string, { id: string; email: string }> = {};
const remote = (email: string) => [...scim.users.values()].find((u) => u.userName === email);
const run = async () => {
  // Retries are scheduled in the future: pull them in, like time passing.
  await owner.query("UPDATE jobs SET run_at = now() WHERE org_id = $1 AND status = 'queued'", [orgId]);
  await h.jobs.runOnce({ orgId });
};
const prov = async () => (await h.call("GET", `/v1/apps/${appId}/provisioning`, { token: admin })).body;
const configure = (over: Record<string, unknown> = {}) =>
  h.call("PUT", `/v1/apps/${appId}/provisioning`, { token: admin, body: { base_url: `${base}/scim/v2`, token: TOKEN, enabled: true, ...over } });

beforeAll(async () => {
  base = await fake.start();
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Initrode", email: uniqueEmail("peter"), password: PASSWORD, given_name: "Peter" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  for (const n of ["ann", "bob", "cy", "dee"]) {
    const email = uniqueEmail(n);
    people[n] = { id: (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: n.toUpperCase(), family_name: "Init", password: PASSWORD } })).body.id, email };
  }
  appId = (await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "oidc", name: "Chat", redirect_uris: ["https://chat.example.com/cb"] } })).body.app.id;
  groupId = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "Engineering" } })).body.id;
  await h.call("POST", `/v1/groups/${groupId}/members`, { token: admin, body: { user_ids: [people.bob!.id, people.cy!.id] } });
  await h.call("POST", `/v1/apps/${appId}/assignments`, { token: admin, body: { principals: [{ type: "user", id: people.ann!.id }, { type: "group", id: groupId }] } });
  // Cy already has an account in the app: it must be adopted, not duplicated.
  scim.users.set("pre1", { id: "pre1", userName: people.cy!.email, active: false });
});
afterAll(async () => {
  fake.stop();
  await owner.end();
  await h.close();
});

describe("configuring provisioning", () => {
  it("checks the endpoint and token first", async () => {
    const bad = await h.call("POST", `/v1/apps/${appId}/provisioning/test`, { token: admin, body: { base_url: `${base}/scim/v2`, token: "wrong" } });
    expect(bad).toMatchObject({ status: 422, body: { code: "scim_unreachable" } });
    expect(bad.body.title).toContain("rejected the provisioning token");
    expect((await h.call("POST", `/v1/apps/${appId}/provisioning/test`, { token: admin, body: { base_url: `${base}/scim/v2`, token: TOKEN } })).status).toBe(204);
    expect((await h.call("PUT", `/v1/apps/${appId}/provisioning`, { token: admin, body: { base_url: "ftp://x", token: TOKEN, enabled: true } })).body.code).toBe("unsafe_url");
  });

  it("provisions everyone assigned, directly or through groups, when turned on", async () => {
    const r = await configure();
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body).toMatchObject({ configured: true, enabled: true, counts: { pending: 3 } });
    expect(JSON.stringify(r.body)).not.toContain(TOKEN);
    await run();

    expect(remote(people.ann!.email)).toMatchObject({ active: true, name: { givenName: "ANN", familyName: "Init" }, externalId: people.ann!.id });
    expect(remote(people.bob!.email)).toMatchObject({ active: true });
    expect(remote(people.cy!.email)).toMatchObject({ id: "pre1", active: true }); // adopted
    expect(remote(people.dee!.email)).toBeUndefined(); // not assigned
    expect([...scim.users.values()].filter((u) => u.userName === people.cy!.email)).toHaveLength(1);

    const g = [...scim.groups.values()][0]!;
    expect(g.displayName).toBe("Engineering");
    expect(g.members.sort()).toEqual([remote(people.bob!.email)!.id, "pre1"].sort());

    const s = await prov();
    expect(s.counts).toEqual({ active: 3, inactive: 0, error: 0, pending: 0 });
    expect(s.groups).toMatchObject([{ display_name: "Engineering" }]);
    expect(s.last_success_at).not.toBeNull();
  });

  it("sends only real changes", async () => {
    scim.requests.length = 0;
    await h.call("POST", `/v1/apps/${appId}/provisioning/sync`, { token: admin, body: {} });
    await run();
    expect(scim.requests.filter((r) => r.startsWith("PATCH /scim/v2/Users") || r.startsWith("POST /scim/v2/Users"))).toEqual([]);
    await h.call("PATCH", `/v1/users/${people.ann!.id}`, { token: admin, body: { title: "Staff Engineer" } });
    await run();
    expect(remote(people.ann!.email)!.title).toBe("Staff Engineer");
  });
});

describe("keeping apps in step", () => {
  it("deactivates people who leave a group, and updates the pushed group", async () => {
    await h.call("DELETE", `/v1/groups/${groupId}/members/${people.bob!.id}`, { token: admin });
    await run();
    expect(remote(people.bob!.email)!.active).toBe(false);
    expect([...scim.groups.values()][0]!.members).toEqual(["pre1"]);
    expect((await prov()).counts).toMatchObject({ active: 2, inactive: 1 });
  });

  it("follows suspension and reactivation", async () => {
    await h.call("POST", `/v1/users/${people.ann!.id}/suspend`, { token: admin, body: {} });
    await run();
    expect(remote(people.ann!.email)!.active).toBe(false);
    await h.call("POST", `/v1/users/${people.ann!.id}/activate`, { token: admin, body: {} });
    await run();
    expect(remote(people.ann!.email)!.active).toBe(true);
  });

  it("recreates an account deleted in the app", async () => {
    scim.users.delete(remote(people.ann!.email)!.id);
    await h.call("PATCH", `/v1/users/${people.ann!.id}`, { token: admin, body: { title: "Principal Engineer" } });
    await run();
    expect(remote(people.ann!.email)).toMatchObject({ active: true, title: "Principal Engineer" });
  });

  it("removes the pushed group and its access when the group is unassigned", async () => {
    await h.call("DELETE", `/v1/apps/${appId}/assignments/group/${groupId}`, { token: admin });
    await run();
    expect(scim.groups.size).toBe(0);
    expect(remote(people.cy!.email)!.active).toBe(false);
    expect((await prov()).groups).toEqual([]);
  });

  it("can delete instead of deactivating", async () => {
    await configure({ token: undefined, on_unassign: "delete" });
    await h.call("DELETE", `/v1/apps/${appId}/assignments/user/${people.ann!.id}`, { token: admin });
    await run();
    expect(remote(people.ann!.email)).toBeUndefined();
    expect((await prov()).accounts.some((a: { user_id: string }) => a.user_id === people.ann!.id)).toBe(false);
  });
});

describe("failures", () => {
  it("retries when the app is briefly down", async () => {
    scim.fail.push(503);
    await h.call("POST", `/v1/apps/${appId}/assignments`, { token: admin, body: { principals: [{ type: "user", id: people.dee!.id }] } });
    await h.jobs.runOnce({ orgId });
    const s = await prov();
    expect(s.accounts.find((a: { user_id: string }) => a.user_id === people.dee!.id)).toMatchObject({ state: "error", last_error: expect.stringContaining("HTTP 503") });
    await run(); // the retry
    expect(remote(people.dee!.email)).toMatchObject({ active: true });
    expect((await prov()).accounts.find((a: { user_id: string }) => a.user_id === people.dee!.id)).toMatchObject({ state: "active", last_error: "" });
  });

  it("stops and tells admins once when the token stops working", async () => {
    scim.fail.push(401, 401);
    await h.call("PATCH", `/v1/users/${people.dee!.id}`, { token: admin, body: { department: "Ops" } });
    await run();
    await h.call("POST", `/v1/apps/${appId}/provisioning/accounts/${people.dee!.id}/retry`, { token: admin, body: {} });
    await run(); // fails again: still one alert
    const s = await prov();
    expect(s.last_error).toContain("rejected the provisioning token");
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=10&filter=all", { token: admin })).body.data.filter((n: { title: string }) => n.title === "Provisioning to Chat is failing");
    expect(inbox).toHaveLength(1);
    const last = await owner.query("SELECT status, attempts FROM jobs WHERE org_id = $1 AND kind = 'scim.user' ORDER BY created_at DESC LIMIT 1", [orgId]);
    expect(last.rows[0]).toEqual({ status: "done", attempts: 1 }); // not retried in a loop

    // Fixed upstream: a retry clears it.
    await h.call("POST", `/v1/apps/${appId}/provisioning/accounts/${people.dee!.id}/retry`, { token: admin, body: {} });
    await run();
    expect(remote(people.dee!.email)!).toMatchObject({ active: true, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { department: "Ops" } });
    expect((await prov()).last_error).toBe("");
  });

  it("only admins configure provisioning", async () => {
    const email = uniqueEmail("hd");
    await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Hd", password: PASSWORD, roles: ["helpdesk"] } });
    const hd = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    expect((await h.call("PUT", `/v1/apps/${appId}/provisioning`, { token: hd, body: { base_url: `${base}/scim/v2`, enabled: false } })).status).toBe(403);
  });
});

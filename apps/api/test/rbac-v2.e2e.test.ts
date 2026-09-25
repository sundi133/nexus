import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** RBAC v2: custom roles (RBAC-02) and roles scoped to groups (RBAC-03). */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let orgId = "";
const P: Record<string, { id: string; email: string; token: string }> = {};
let emea = "";
const devices: Record<string, string> = {};

async function person(name: string, roles: string[] = []) {
  const email = uniqueEmail(name);
  const id = (await h.call("POST", "/v1/users", { token: P.root!.token, body: { email, given_name: name, password: PASSWORD, roles } })).body.id;
  P[name] = { id, email, token: "" };
}
const login = async (name: string) => (P[name]!.token = (await h.call("POST", "/v1/auth/login", { body: { email: P[name]!.email, password: PASSWORD } })).body.token);
const as = (name: string) => P[name]!.token;
const grant = (who: string, grants: unknown[], by = "root") => h.call("PUT", `/v1/users/${P[who]!.id}/role-grants`, { token: as(by), body: { grants } });

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("root");
  const token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Roles Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token })).body;
  orgId = me.organization.id;
  P.root = { id: me.user.id, email, token };
  await person("admin", ["admin"]);
  for (const n of ["helper", "devops", "emma", "eli", "amy"]) await person(n);
  emea = (await h.call("POST", "/v1/groups", { token, body: { name: "EMEA" } })).body.id;
  await h.call("POST", `/v1/groups/${emea}/members`, { token, body: { user_ids: [P.emma!.id, P.eli!.id] } });
  // A device each for emma (EMEA) and amy (not).
  for (const [n, u] of [["emma-mac", P.emma!.id], ["amy-mac", P.amy!.id]] as const) {
    devices[n] = randomUUID();
    await owner.query("INSERT INTO devices (id, org_id, hostname, platform, public_jwk, key_thumbprint, primary_user_id, updated_at) VALUES ($1, $2, $3, 'macos', '{}', $4, $5, now())", [devices[n], orgId, n, randomUUID(), u]);
  }
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("custom roles", () => {
  let roleId = "";
  it("are built from the permission catalog, without owner-only powers", async () => {
    const cat = (await h.call("GET", "/v1/roles", { token: as("root") })).body;
    expect(cat.builtin.find((b: any) => b.key === "helpdesk")).toMatchObject({ scopable: true });
    expect(cat.permissions.find((x: any) => x.key === "admins:manage")).toMatchObject({ in_custom_roles: false });
    expect((await h.call("POST", "/v1/roles", { token: as("root"), body: { name: "Sneaky", permissions: ["admins:manage"] } })).body.code).toBe("not_allowed");
    const r = await h.call("POST", "/v1/roles", { token: as("root"), body: { name: "Device operator", permissions: ["devices:read", "devices:actions", "users:read"] } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    roleId = r.body.custom[0].id;
  });

  it("only owners grant them", async () => {
    await login("admin");
    expect((await grant("devops", [{ role: `custom:${roleId}` }], "admin")).status).toBe(403);
    const g = await grant("devops", [{ role: `custom:${roleId}` }]);
    expect(g.body.data).toMatchObject([{ role: `custom:${roleId}`, name: "Device operator", scope: [] }]);
    expect((await h.call("GET", "/v1/audit/events?type=user.roles_changed", { token: as("root") })).body.data[0].details.grants).toEqual({ from: [], to: ["Device operator"] });
  });

  it("give exactly their permissions, and changes apply at once", async () => {
    await login("devops");
    const me = (await h.call("GET", "/v1/me", { token: as("devops") })).body;
    expect(me.permissions.sort()).toEqual(["devices:actions", "devices:read", "users:read"]);
    expect((await h.call("GET", "/v1/devices", { token: as("devops") })).status).toBe(200);
    expect((await h.call("POST", "/v1/groups", { token: as("devops"), body: { name: "x" } })).status).toBe(403);
    await h.call("PATCH", `/v1/roles/${roleId}`, { token: as("root"), body: { permissions: ["users:read"] } });
    expect((await h.call("GET", "/v1/devices", { token: as("devops") })).status).toBe(403);
    await h.call("DELETE", `/v1/roles/${roleId}`, { token: as("root") });
    expect((await h.call("GET", "/v1/users", { token: as("devops") })).status).toBe(403);
    expect((await h.call("GET", `/v1/users/${P.devops!.id}/role-grants`, { token: as("root") })).body.data).toEqual([]);
  });
});

describe("a Help Desk scoped to EMEA", () => {
  it("needs groups for a built-in role", async () => {
    expect((await grant("helper", [{ role: "helpdesk" }])).body.code).toBe("scope_required");
    expect((await grant("helper", [{ role: "helpdesk", scope_group_ids: [emea] }])).status).toBe(200);
    await login("helper");
    const me = (await h.call("GET", "/v1/me", { token: as("helper") })).body;
    expect(me.roles).toEqual([]);
    expect(me.scoped_permissions["users:lifecycle"]).toEqual([emea]);
    expect(me.permissions).toEqual(expect.arrayContaining(["groups:read", "apps:read"]));
    expect(me.permissions).not.toContain("audit:read"); // would see everyone: dropped in a scoped grant
  });

  it("sees only the people in the group", async () => {
    const list = (await h.call("GET", "/v1/users", { token: as("helper") })).body.data.map((u: any) => u.email).sort();
    expect(list).toEqual([P.eli!.email, P.emma!.email].sort());
    expect((await h.call("GET", `/v1/users/${P.emma!.id}`, { token: as("helper") })).status).toBe(200);
    expect((await h.call("GET", `/v1/users/${P.amy!.id}`, { token: as("helper") })).status).toBe(404);
  });

  it("acts only on people in the group", async () => {
    expect((await h.call("POST", `/v1/users/${P.eli!.id}/suspend`, { token: as("helper"), body: { reason: "ticket 12" } })).status).toBe(200);
    expect((await h.call("POST", `/v1/users/${P.amy!.id}/suspend`, { token: as("helper"), body: {} })).status).toBe(404);
    expect((await h.call("PATCH", `/v1/users/${P.emma!.id}`, { token: as("helper"), body: { title: "Engineer" } })).status).toBe(200);
    expect((await h.call("GET", `/v1/users/${P.amy!.id}/offboarding`, { token: as("helper") })).status).toBe(404);
    expect((await h.call("GET", `/v1/users/${P.emma!.id}/offboarding`, { token: as("helper") })).status).toBe(200);
  });

  it("sees and acts on the group's devices only", async () => {
    const list = (await h.call("GET", "/v1/devices", { token: as("helper") })).body.data.map((d: any) => d.hostname);
    expect(list).toEqual(["emma-mac"]);
    expect((await h.call("GET", `/v1/devices/${devices["amy-mac"]}`, { token: as("helper") })).status).toBe(404);
    expect((await h.call("POST", `/v1/devices/${devices["amy-mac"]}/actions`, { token: as("helper"), body: { action: "refresh" } })).status).toBe(404);
  });

  it("is refused wherever a route hasn't opted into scopes", async () => {
    expect((await h.call("POST", "/v1/users", { token: as("helper"), body: { email: uniqueEmail("x"), given_name: "x" } })).status).toBe(403); // new people aren't in the group
    expect((await h.call("GET", "/v1/audit/events", { token: as("helper") })).status).toBe(403);
    expect((await h.call("POST", `/v1/groups/${emea}/members`, { token: as("helper"), body: { user_ids: [P.amy!.id] } })).status).toBe(403); // can't widen its own scope
  });
});

describe("governance", () => {
  it("puts custom and scoped roles in admin access reviews, and revokes them", async () => {
    const r = (await h.call("POST", "/v1/access-reviews", { token: as("root"), body: { name: "Admins", scope: { type: "admin_roles" }, reviewers: { kind: "users", ids: [P.root!.id] } } })).body;
    const items = (await h.call("GET", `/v1/access-reviews/${r.id}`, { token: as("root") })).body.items;
    const item = items.find((i: any) => i.user.id === P.helper!.id);
    expect(item.access).toBe("helpdesk role for EMEA");
    await h.call("POST", `/v1/access-reviews/${r.id}/decisions`, { token: as("root"), body: { items: [{ id: item.id, decision: "revoke" }] } });
    await h.call("POST", `/v1/access-reviews/${r.id}/close`, { token: as("root"), body: {} });
    expect((await h.call("GET", "/v1/users", { token: as("helper") })).status).toBe(403);
  });

  it("removes grants when someone is offboarded", async () => {
    await grant("emma", [{ role: "readonly", scope_group_ids: [emea] }]);
    await h.call("POST", `/v1/users/${P.emma!.id}/offboard`, { token: as("root"), body: { reason: "left" } });
    expect((await owner.query("SELECT count(*)::int AS n FROM role_grants WHERE user_id = $1", [P.emma!.id])).rows[0].n).toBe(0);
  });
});

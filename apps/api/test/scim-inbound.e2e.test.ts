import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Inbound SCIM 2.0 (DIR-07): Okta and Entra ID push people and groups into Nexus. */

const RUN = randomUUID().slice(0, 8);
const at = (name: string) => `${name}-${RUN}@acme-scim.test`;
const ENT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";
let connId = "";
let token = "";

type Res = { status: number; body: any; headers: Headers };
async function scim(method: string, path: string, body?: unknown, t = token): Promise<Res> {
  const res = await h.app.request(`/scim/v2${path}`, {
    method,
    headers: { authorization: `Bearer ${t}`, "content-type": "application/scim+json", accept: "application/scim+json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers };
}
const oktaUser = (email: string, extra: Record<string, unknown> = {}) => ({
  schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  userName: email,
  name: { givenName: "Ada", familyName: "Lovelace" },
  emails: [{ primary: true, value: email, type: "work" }],
  displayName: "Ada Lovelace",
  active: true,
  externalId: `00u${randomUUID().slice(0, 6)}`,
  ...extra,
});
const user = async (id: string) => (await h.call("GET", `/v1/users/${id}`, { token: admin })).body;
const conn = async () => ((await h.call("GET", "/v1/directory/connections", { token: admin })).body.data as any[]).find((x) => x.id === connId);

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "SCIM Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("setting up", () => {
  it("creates a SCIM connection with a token shown once", async () => {
    const r = await h.call("POST", "/v1/directory/scim", { token: admin, body: { name: "Okta" } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    token = r.body.scim.token;
    expect(token).toMatch(/^nxscim_[A-Za-z0-9_-]{43}$/);
    expect(r.body.scim.base_url).toMatch(/\/scim\/v2$/);
    const c = r.body.data.find((x: any) => x.provider === "scim");
    connId = c.id;
    expect(c).toMatchObject({ provider_name: "SCIM", name: "Okta", enabled: true, next_sync_at: null, scim: { token_hint: token.slice(-4), last_request_at: null } });
    expect(JSON.stringify((await h.call("GET", "/v1/directory/connections", { token: admin })).body)).not.toContain(token);
    // Nothing to pull.
    expect((await h.call("POST", `/v1/directory/connections/${connId}/preview`, { token: admin, body: {} })).body.code).toBe("scim_push");
  });

  it("needs the token, and says so in SCIM's error format", async () => {
    const none = await scim("GET", "/Users", undefined, "");
    expect(none.status).toBe(401);
    expect(none.body).toEqual({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "401", detail: "A valid SCIM bearer token is required" });
    expect((await scim("GET", "/Users", undefined, "nxscim_forged")).status).toBe(401);
    const cfg = await scim("GET", "/ServiceProviderConfig");
    expect(cfg.headers.get("content-type")).toContain("application/scim+json");
    expect(cfg.body).toMatchObject({ patch: { supported: true }, filter: { supported: true }, bulk: { supported: false } });
    expect((await conn()).scim.last_request_at).not.toBeNull();
  });
});

describe("users (the Okta way)", () => {
  let adaId = "";
  const ada = at("ada");

  it("looks up, then creates, and invites", async () => {
    const miss = await scim("GET", `/Users?filter=${encodeURIComponent(`userName eq "${ada}"`)}&startIndex=1&count=100`);
    expect(miss.body).toMatchObject({ totalResults: 0, Resources: [] });
    const mails = h.deps.mailer.sent.length;
    const r = await scim("POST", "/Users", oktaUser(ada, { title: "Engineer", [ENT]: { department: "R&D" } }));
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    adaId = r.body.id;
    expect(r.headers.get("location")).toBe(r.body.meta.location);
    expect(r.body).toMatchObject({ userName: ada, active: true, name: { givenName: "Ada" }, title: "Engineer", [ENT]: { department: "R&D" } });
    expect(await user(adaId)).toMatchObject({ email: ada, status: "staged", department: "R&D" });
    expect(h.deps.mailer.sent.length).toBe(mails + 1); // invitation
    const ev = (await h.call("GET", "/v1/audit/events?type=user.created", { token: admin })).body.data[0];
    expect(ev).toMatchObject({ actor: { display: "SCIM · Okta" }, details: { via: "scim", connection_id: connId } });
    // Found now, by userName, email or externalId; and it's a conflict to create twice.
    const hit = await scim("GET", `/Users?filter=${encodeURIComponent(`userName eq "${ada.toUpperCase()}"`)}`);
    expect(hit.body.totalResults).toBe(1);
    expect((await scim("GET", `/Users?filter=${encodeURIComponent(`externalId eq "${r.body.externalId}"`)}`)).body.Resources[0].id).toBe(adaId);
    expect((await scim("POST", "/Users", oktaUser(ada))).body).toMatchObject({ status: "409", scimType: "uniqueness" });
  });

  it("refuses emails that belong to another organization", async () => {
    const other = uniqueEmail("elsewhere");
    await h.call("POST", "/v1/signup", { body: { organization_name: "Else", email: other, password: PASSWORD, given_name: "E" } });
    expect((await scim("POST", "/Users", oktaUser(other))).body).toMatchObject({ status: "409", scimType: "uniqueness", detail: expect.stringContaining("another Nexus organization") });
  });

  it("applies Entra-style PATCH: names, department, email, string booleans", async () => {
    const r = await scim("PATCH", `/Users/${adaId}`, {
      schemas: [PATCH],
      Operations: [
        { op: "Replace", path: "name.givenName", value: "Augusta" },
        { op: "Add", path: `${ENT}:department`, value: "Mathematics" },
        { op: "Replace", path: 'emails[type eq "work"].value', value: at("augusta") },
      ],
    });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(await user(adaId)).toMatchObject({ given_name: "Augusta", department: "Mathematics", email: at("augusta") });
    const ev = (await h.call("GET", "/v1/audit/events?type=user.updated", { token: admin })).body.data[0];
    expect(ev.details.changes).toMatchObject({ given_name: { from: "Ada", to: "Augusta" }, email: { to: at("augusta") } });
  });

  it("deactivates and reactivates, but never undoes an admin's suspension", async () => {
    // Give Ada a session to revoke.
    await owner.query("UPDATE users SET status = 'active', password_hash = (SELECT password_hash FROM users WHERE org_id = $1 AND password_hash IS NOT NULL LIMIT 1) WHERE id = $2", [orgId, adaId]);
    const s = (await h.call("POST", "/v1/auth/login", { body: { email: at("augusta"), password: PASSWORD } })).body.token;
    expect((await h.call("GET", "/v1/me", { token: s })).status).toBe(200);
    const off = await scim("PATCH", `/Users/${adaId}`, { schemas: [PATCH], Operations: [{ op: "Replace", path: "active", value: "False" }] });
    expect(off.body.active).toBe(false);
    expect((await user(adaId)).status).toBe("suspended");
    expect((await h.call("GET", "/v1/me", { token: s })).status).toBe(401); // signed out
    await scim("PATCH", `/Users/${adaId}`, { schemas: [PATCH], Operations: [{ op: "replace", value: { active: true } }] });
    expect((await user(adaId)).status).toBe("active");

    // An admin suspends; the IdP still says active: the admin wins.
    await h.call("POST", `/v1/users/${adaId}/suspend`, { token: admin, body: {} });
    await scim("PUT", `/Users/${adaId}`, oktaUser(at("augusta"), { active: true }));
    expect((await user(adaId)).status).toBe("suspended");
    await h.call("POST", `/v1/users/${adaId}/activate`, { token: admin, body: {} });
  });

  it("offboards on DELETE", async () => {
    const r = await scim("DELETE", `/Users/${adaId}`);
    expect(r.status).toBe(204);
    expect((await user(adaId)).status).toBe("deprovisioned");
    expect((await scim("GET", `/Users/${adaId}`)).status).toBe(404);
    const ev = (await h.call("GET", "/v1/audit/events?type=user.offboarded", { token: admin })).body.data[0];
    expect(ev).toMatchObject({ actor: { display: "SCIM · Okta" }, details: { reason: "Deleted in Okta", connection_id: connId } });
  });

  it("can't see or touch break-glass accounts", async () => {
    const me = (await h.call("GET", "/v1/me", { token: admin })).body.user;
    await owner.query("UPDATE users SET break_glass = true WHERE id = $1", [me.id]);
    expect((await scim("GET", `/Users/${me.id}`)).status).toBe(404);
    expect((await scim("GET", "/Users")).body.Resources.some((u: any) => u.id === me.id)).toBe(false);
    expect((await scim("PATCH", `/Users/${me.id}`, { schemas: [PATCH], Operations: [{ op: "replace", value: { active: false } }] })).status).toBe(404);
    await owner.query("UPDATE users SET break_glass = false WHERE id = $1", [me.id]);
  });
});

describe("groups", () => {
  let gid = "";
  const ids: string[] = [];

  it("creates groups with members, and finds them the way each IdP asks", async () => {
    for (const n of ["g1", "g2", "g3"]) ids.push((await scim("POST", "/Users", oktaUser(at(n)))).body.id);
    const r = await scim("POST", "/Groups", { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: `Engineering ${RUN}`, externalId: "00g1", members: [{ value: ids[0] }, { value: ids[1] }] });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    gid = r.body.id;
    expect(r.body.members.map((m: any) => m.value).sort()).toEqual([ids[0], ids[1]].sort());
    const byName = await scim("GET", `/Groups?filter=${encodeURIComponent(`displayName eq "engineering ${RUN}"`)}&excludedAttributes=members`);
    expect(byName.body.Resources).toEqual([expect.objectContaining({ id: gid, externalId: "00g1" })]);
    expect(byName.body.Resources[0].members).toBeUndefined();
    // Entra checks membership like this.
    const member = await scim("GET", `/Groups?filter=${encodeURIComponent(`id eq "${gid}" and members[value eq "${ids[0]}"]`)}&excludedAttributes=members`);
    expect(member.body.totalResults).toBe(1);
    const notMember = await scim("GET", `/Groups?filter=${encodeURIComponent(`id eq "${gid}" and members[value eq "${ids[2]}"]`)}`);
    expect(notMember.body.totalResults).toBe(0);
    expect((await scim("GET", `/Users/${ids[0]}`)).body.groups).toEqual([expect.objectContaining({ value: gid, display: `Engineering ${RUN}` })]);
  });

  it("applies membership and name changes from Okta and Entra", async () => {
    await scim("PATCH", `/Groups/${gid}`, { schemas: [PATCH], Operations: [{ op: "add", path: "members", value: [{ value: ids[2] }] }, { op: "remove", path: `members[value eq "${ids[0]}"]` }] });
    await scim("PATCH", `/Groups/${gid}`, { schemas: [PATCH], Operations: [{ op: "Remove", path: "members", value: [{ value: ids[1] }] }, { op: "Replace", path: "displayName", value: `Eng ${RUN}` }] });
    const g = await scim("GET", `/Groups/${gid}`);
    expect(g.body).toMatchObject({ displayName: `Eng ${RUN}`, members: [{ value: ids[2] }] });
    const ev = (await h.call("GET", "/v1/audit/events?type=group.updated", { token: admin })).body.data[0];
    expect(ev.details).toMatchObject({ removed: 1, renamed: { from: `Engineering ${RUN}`, to: `Eng ${RUN}` } });
    // PUT replaces the whole membership.
    await scim("PUT", `/Groups/${gid}`, { displayName: `Eng ${RUN}`, members: [{ value: ids[0] }, { value: ids[1] }] });
    expect((await scim("GET", `/Groups/${gid}`)).body.members.map((m: any) => m.value).sort()).toEqual([ids[0], ids[1]].sort());
    expect((await scim("POST", "/Groups", { displayName: `eng ${RUN}` })).body.scimType).toBe("uniqueness");
  });

  it("deletes groups", async () => {
    expect((await scim("DELETE", `/Groups/${gid}`)).status).toBe(204);
    expect((await scim("GET", `/Groups/${gid}`)).status).toBe(404);
    expect((await h.call("GET", `/v1/groups/${gid}`, { token: admin })).status).toBe(404);
  });
});

describe("safety", () => {
  it("pauses a burst of deactivations until an admin approves", async () => {
    const people: string[] = [];
    for (let i = 0; i < 8; i++) people.push((await scim("POST", "/Users", oktaUser(at(`burst${i}`)))).body.id);
    const deactivate = (id: string) => scim("PATCH", `/Users/${id}`, { schemas: [PATCH], Operations: [{ op: "replace", path: "active", value: false }] });
    const results: number[] = [];
    for (const id of people) results.push((await deactivate(id)).status);
    const firstHeld = results.indexOf(429);
    expect(firstHeld).toBeGreaterThan(0);
    const held = await deactivate(people.at(-1)!);
    expect(held.status).toBe(429);
    expect(held.headers.get("retry-after")).toBe("300");
    expect((await user(people.at(-1)!)).status).toBe("staged"); // not deactivated
    expect(await conn()).toMatchObject({ last_status: "needs_approval", last_error: expect.stringContaining("Paused deactivations") });
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin })).body.data;
    expect(inbox.filter((n: any) => n.title === "Okta is deactivating many people")).toHaveLength(1); // once, not per request

    const ok = await h.call("POST", `/v1/directory/connections/${connId}/sync`, { token: admin, body: { approved_suspensions: 50 } });
    expect(ok.status, JSON.stringify(ok.body)).toBe(202);
    expect(await conn()).toMatchObject({ last_status: "ok", scim: { deactivations_allowed_until: expect.any(String) } });
    expect((await deactivate(people.at(-1)!)).status).toBe(200);
    expect((await user(people.at(-1)!)).status).toBe("suspended");
  });

  it("follows the deprovisioning setting", async () => {
    await h.call("PATCH", `/v1/directory/connections/${connId}`, { token: admin, body: { deprovision: "none" } });
    const id = (await scim("POST", "/Users", oktaUser(at("kept")))).body.id;
    await scim("PATCH", `/Users/${id}`, { schemas: [PATCH], Operations: [{ op: "replace", path: "active", value: false }] });
    expect((await user(id)).status).toBe("staged");
    expect((await scim("DELETE", `/Users/${id}`)).status).toBe(204);
    expect((await user(id)).status).toBe("staged"); // just no longer managed by Okta
    await h.call("PATCH", `/v1/directory/connections/${connId}`, { token: admin, body: { deprovision: "suspend" } });
  });

  it("rotates the token, and stops when turned off", async () => {
    const r = await h.call("POST", `/v1/directory/connections/${connId}/scim-token`, { token: admin, body: {} });
    expect((await scim("GET", "/Users")).status).toBe(401);
    token = r.body.token;
    expect((await scim("GET", "/Users")).status).toBe(200);
    await h.call("PATCH", `/v1/directory/connections/${connId}`, { token: admin, body: { enabled: false } });
    expect((await scim("GET", "/Users")).body).toMatchObject({ status: "403", detail: expect.stringContaining("turned off") });
    await h.call("PATCH", `/v1/directory/connections/${connId}`, { token: admin, body: { enabled: true } });
  });

  it("stays inside its organization", async () => {
    const other = (await h.call("POST", "/v1/signup", { body: { organization_name: "Other", email: uniqueEmail("o"), password: PASSWORD, given_name: "O" } })).body.token;
    await h.call("PATCH", "/v1/org/settings", { token: other, body: { mfa_policy: "off" } });
    const otherUser = (await h.call("GET", "/v1/me", { token: other })).body.user.id;
    expect((await scim("GET", `/Users/${otherUser}`)).status).toBe(404);
    expect((await scim("PATCH", `/Users/${otherUser}`, { schemas: [PATCH], Operations: [{ op: "replace", value: { active: false } }] })).status).toBe(404);
    expect((await scim("GET", "/Users")).body.Resources.some((u: any) => u.id === otherUser)).toBe(false);
  });

  it("doesn't send invitations when the organization's IdP signs people in", async () => {
    const domain = `fed-${RUN}.test`;
    await owner.query("INSERT INTO org_domains (id, org_id, domain, token, status, verified_at) VALUES ($1, $2, $3, 'x', 'verified', now())", [randomUUID(), orgId, domain]);
    await owner.query(
      "INSERT INTO identity_providers (id, org_id, name, protocol, idp_entity_id, idp_sso_url, idp_certs, domains) VALUES ($1, $2, 'Okta SSO', 'saml', 'https://okta.example.com', 'https://okta.example.com/sso', ARRAY['x'], ARRAY[$3])",
      [randomUUID(), orgId, domain],
    );
    const mails = h.deps.mailer.sent.length;
    const r = await scim("POST", "/Users", oktaUser(`sso-person@${domain}`));
    expect(r.status).toBe(201);
    expect(h.deps.mailer.sent.length).toBe(mails); // they'll sign in with Okta
  });
});

describe("protecting owners and admins", () => {
  it("won't change an admin's email, or suspend or delete the last owner", async () => {
    const rootId = (await h.call("GET", "/v1/me", { token: admin })).body.user.id;
    const before = await user(rootId);
    const emailChange = await scim("PATCH", `/Users/${rootId}`, { schemas: [PATCH], Operations: [{ op: "replace", value: { userName: at("attacker"), emails: [{ value: at("attacker"), primary: true, type: "work" }] } }] });
    expect(emailChange.status).toBeLessThan(300); // accepted, but the email stays
    expect((await user(rootId)).email).toBe(before.email);
    await scim("PATCH", `/Users/${rootId}`, { schemas: [PATCH], Operations: [{ op: "replace", path: "active", value: false }] });
    expect((await user(rootId)).status).toBe("active");
    expect((await scim("DELETE", `/Users/${rootId}`)).status).toBe(409);
    expect((await user(rootId)).status).toBe("active");
    const refused = (await h.call("GET", "/v1/audit/events?type=directory.change_refused", { token: admin })).body.data.map((e: any) => e.details.reason);
    expect(refused).toEqual(expect.arrayContaining(["email of an admin", "last owner"]));
  });
});

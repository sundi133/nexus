import { gunzipSync } from "node:zlib";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Data governance: privacy requests about a person (export, erasure), and exporting the organization. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let owner = "";
let ownerId = "";
let orgId = "";
let helpdesk = "";
const pat = { id: "", email: "" };
let laptopId = "";
let groupId = "";

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  owner = (await h.call("POST", "/v1/signup", { body: { organization_name: "Initech", email: uniqueEmail("bill"), password: PASSWORD, given_name: "Bill" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: owner, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token: owner })).body;
  orgId = me.organization.id;
  ownerId = me.user.id;

  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: owner, body: { email: hd, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;

  // Pat: signed in, with a TOTP factor, in a group, with a laptop.
  pat.email = uniqueEmail("pat");
  pat.id = (await h.call("POST", "/v1/users", { token: owner, body: { email: pat.email, given_name: "Pat", family_name: "Lee", password: PASSWORD } })).body.id;
  const patToken = (await h.call("POST", "/v1/auth/login", { body: { email: pat.email, password: PASSWORD } })).body.token;
  const f = await h.call("POST", "/v1/me/factors/totp", { token: patToken, body: {} });
  await h.call("POST", `/v1/me/factors/${f.body.id}/verify`, { token: patToken, body: { code: totpCode(f.body.secret) } });
  groupId = (await h.call("POST", "/v1/groups", { token: owner, body: { name: "Accounting" } })).body.id;
  await h.call("POST", `/v1/groups/${groupId}/members`, { token: owner, body: { user_ids: [pat.id] } });
  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: owner, body: { name: "laptops" } })).body.token;
  const d = await new SoftDevice().init();
  const payload = JSON.stringify({ token: t, device: { hostname: "pats-laptop", platform: "macos" } });
  const res = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof("/v1/agent/enroll", payload, { enroll: true })}` }, body: payload });
  laptopId = ((await res.json()) as { device_id: string }).device_id;
  await h.call("PATCH", `/v1/devices/${laptopId}`, { token: owner, body: { primary_user_id: pat.id } });
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("a person's data (privacy access request)", () => {
  it("exports everything about them, without secrets, and records it", async () => {
    const r = await h.call("GET", `/v1/users/${pat.id}/data-export`, { token: owner });
    expect(r.status).toBe(200);
    expect(r.headers.get("content-disposition")).toContain(`person-${pat.id}.json`);
    const e = r.body;
    expect(e.format).toBe("nexus-person-export/1");
    expect(e.data.users).toEqual([expect.objectContaining({ id: pat.id, email: pat.email, given_name: "Pat", family_name: "Lee" })]);
    expect(e.data.group_members).toEqual([expect.objectContaining({ group_id: groupId })]);
    expect(e.data.auth_factors).toEqual([expect.objectContaining({ type: "totp" })]);
    expect(e.data.sessions.length).toBeGreaterThan(0);
    expect(e.data.devices).toEqual([expect.objectContaining({ id: laptopId, hostname: "pats-laptop" })]);
    expect(e.audit_events.map((a: { type: string }) => a.type)).toEqual(expect.arrayContaining(["user.created", "auth.login"]));
    // No secrets anywhere, and the export says what it left out.
    const text = JSON.stringify(e);
    for (const k of ["password_hash", "secret_sealed", "token_hash", "public_key"]) expect(text).not.toContain(`"${k}":`);
    expect(e.omitted.users).toContain("password_hash");
    expect(e.omitted.auth_factors).toContain("secret_sealed");
    expect(e.omitted.sessions).toContain("token_hash");
    // Direct reports aren't part of someone's own data.
    expect(e.data.users).toHaveLength(1);
    const logged = await db.query("SELECT details FROM audit_events WHERE org_id = $1 AND type = 'user.data_exported' AND target_id = $2", [orgId, pat.id]);
    expect(logged.rows).toHaveLength(1);
  });

  it("needs users:read", async () => {
    const other = uniqueEmail("ro");
    await h.call("POST", "/v1/users", { token: owner, body: { email: other, given_name: "Ro", password: PASSWORD } });
    const t = (await h.call("POST", "/v1/auth/login", { body: { email: other, password: PASSWORD } })).body.token;
    expect((await h.call("GET", `/v1/users/${pat.id}/data-export`, { token: t })).status).toBe(403);
  });
});

describe("erasing a person (privacy erasure request)", () => {
  const erase = (token: string, id: string, confirm: string) => h.call("POST", `/v1/users/${id}/erase`, { token, body: { confirm, reason: "GDPR Art. 17 request PRIV-7" } });

  it("is refused without users:erase, for yourself, and while they're still active", async () => {
    expect((await erase(helpdesk, pat.id, pat.email)).status).toBe(403);
    expect((await erase(owner, ownerId, "x")).body.code).toBe("cannot_target_self");
    expect((await erase(owner, pat.id, pat.email)).body.code).toBe("still_active");
  });

  it("needs the email typed exactly", async () => {
    await h.call("POST", `/v1/users/${pat.id}/suspend`, { token: owner, body: { reason: "leaving" } });
    expect((await erase(owner, pat.id, "someone@else.test")).body.code).toBe("confirmation_mismatch");
  });

  it("deletes their personal data, keeps the organization's records without them, and audits it by ID only", async () => {
    const r = await erase(owner, pat.id, pat.email.toUpperCase());
    expect(r.status).toBe(200);
    expect(r.body.removed).toMatchObject({ users: 1, auth_factors: 1, group_members: 1 });
    expect(r.body.removed.sessions).toBeGreaterThan(0);
    expect(r.body.detached).toMatchObject({ "devices.primary_user_id": 1 });
    expect(r.body.directory_managed).toBe(false);

    expect((await h.call("GET", `/v1/users/${pat.id}`, { token: owner })).status).toBe(404);
    for (const [table, col] of [["users", "id"], ["sessions", "user_id"], ["auth_factors", "user_id"], ["group_members", "user_id"], ["user_roles", "user_id"]]) {
      expect((await db.query(`SELECT 1 FROM ${table} WHERE ${col} = $1`, [pat.id])).rowCount, table).toBe(0);
    }
    // The laptop is the organization's: it stays, unassigned.
    expect((await db.query("SELECT primary_user_id FROM devices WHERE id = $1", [laptopId])).rows[0]).toEqual({ primary_user_id: null });
    const ev = (await db.query("SELECT target_display, details FROM audit_events WHERE org_id = $1 AND type = 'user.erased'", [orgId])).rows;
    expect(ev).toHaveLength(1);
    expect(ev[0].target_display).toBe("erased person");
    expect(JSON.stringify(ev[0])).not.toContain(pat.email.split("@")[0]);
    expect((await erase(owner, pat.id, pat.email)).status).toBe(404);
  });
});

describe("exporting the organization", () => {
  const exportAs = (token: string) => h.app.request("/v1/org/export", { headers: { authorization: `Bearer ${token}` } });

  it("needs data:export", async () => {
    expect((await exportAs(helpdesk)).status).toBe(403);
  });

  it("streams every table of this organization only, without secrets, framed so truncation shows", async () => {
    const r = await exportAs(owner);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("application/gzip");
    expect(r.headers.get("content-disposition")).toMatch(/attachment; filename="nexus-.+\.ndjson\.gz"/);
    const lines = gunzipSync(Buffer.from(await r.arrayBuffer())).toString("utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lines[0]).toMatchObject({ type: "manifest", format: "nexus-org-export/1", organization: { id: orgId, name: "Initech" } });
    const end = lines.at(-1);
    expect(end.type).toBe("end");

    const rows = lines.filter((l) => l.type === "row");
    const tables = lines.filter((l) => l.type === "table").map((l) => l.table);
    expect(tables).toEqual(expect.arrayContaining(["users", "groups", "group_members", "devices", "audit_events", "user_roles"]));
    for (const t of ["jobs", "oidc_codes", "rate_limits", "agent_nonces"]) expect(tables).not.toContain(t);
    // Counts match the rows, and the database.
    for (const [t, n] of Object.entries(end.counts)) expect(rows.filter((l) => l.table === t).length, t).toBe(n);
    const users = Number((await db.query("SELECT count(*) FROM users WHERE org_id = $1", [orgId])).rows[0].count);
    expect(end.counts.users).toBe(users);
    // Only this organization's rows (other tests' organizations share the database).
    expect(rows.every((l) => l.row.org_id === orgId)).toBe(true);
    // No secrets, and each table says what it left out.
    expect(rows.some((l) => "password_hash" in l.row || "secret_sealed" in l.row || "token_hash" in l.row || "private_key" in l.row)).toBe(false);
    expect(lines.find((l) => l.type === "table" && l.table === "users").omitted).toContain("password_hash");
    expect((await db.query("SELECT 1 FROM audit_events WHERE org_id = $1 AND type = 'organization.exported'", [orgId])).rowCount).toBe(1);
  });
});

import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Scoped, expiring API keys (INT-02). */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let key = "";
let keyId = "";

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Dunder", email: uniqueEmail("michael"), password: PASSWORD, given_name: "Michael" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("API keys", () => {
  it("are created with scopes you hold, shown once", async () => {
    const list = await h.call("GET", "/v1/api-keys", { token: admin });
    expect(list.body.grantable_scopes).toContain("users:lifecycle");
    expect(list.body.grantable_scopes).not.toContain("admins:manage");
    expect(list.body.grantable_scopes).not.toContain("api_keys:manage");

    const r = await h.call("POST", "/v1/api-keys", { token: admin, body: { name: "HR offboarding", scopes: ["users:read", "users:lifecycle"], expires_in_days: 30 } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    key = r.body.key;
    keyId = r.body.api_key.id;
    expect(key).toMatch(/^nxk_[A-Za-z0-9_-]{43}$/);
    expect(r.body.api_key).toMatchObject({ name: "HR offboarding", prefix: key.slice(0, 12), scopes: ["users:lifecycle", "users:read"], status: "active" });
    expect(JSON.stringify((await h.call("GET", "/v1/api-keys", { token: admin })).body)).not.toContain(key);
  });

  it("refuse scopes that would let a key entrench itself", async () => {
    for (const scopes of [["admins:manage"], ["api_keys:manage"], ["not:a:scope"]]) {
      expect((await h.call("POST", "/v1/api-keys", { token: admin, body: { name: `bad ${scopes[0]}`, scopes } })).status).toBe(400);
    }
    const email = uniqueEmail("hd");
    await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Hd", password: PASSWORD, roles: ["helpdesk"] } });
    const hd = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    expect((await h.call("POST", "/v1/api-keys", { token: hd, body: { name: "x", scopes: ["users:read"] } })).status).toBe(403);
  });

  it("act within their scopes, and only there", async () => {
    expect((await h.call("GET", "/v1/users", { token: key })).status).toBe(200);
    const denied = await h.call("POST", "/v1/users", { token: key, body: { email: uniqueEmail("x"), given_name: "X" } });
    expect(denied).toMatchObject({ status: 403, body: { title: "This API key doesn't have the users:write scope" } });
    // Personal endpoints are off-limits: a key never acts as the person who made it.
    for (const path of ["/v1/me", "/v1/me/factors", "/v1/me/sessions", "/v1/me/apps"]) {
      expect((await h.call("GET", path, { token: key })).status, path).toBe(403);
    }
    expect((await h.call("GET", "/v1/api-keys", { token: key })).status).toBe(403);
  });

  it("can run lifecycle automation, audited as the key", async () => {
    const email = uniqueEmail("leaver");
    const id = (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Leaver", password: PASSWORD } })).body.id;
    const r = await h.call("POST", `/v1/users/${id}/offboard`, { token: key, body: { reason: "HRIS termination" } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const ev = (await h.call("GET", "/v1/audit/events?type=user.offboarded", { token: admin })).body.data[0];
    expect(ev.actor).toMatchObject({ type: "api_key", id: keyId, display: "API key “HR offboarding”" });
    const k = (await h.call("GET", "/v1/api-keys", { token: admin })).body.data[0];
    expect(k.last_used_at).not.toBeNull();
  });

  it("stop working when revoked or expired", async () => {
    const other = (await h.call("POST", "/v1/api-keys", { token: admin, body: { name: "Reporting", scopes: ["users:read"] } })).body;
    await owner.query("UPDATE api_keys SET expires_at = now() - interval '1 second' WHERE id = $1", [other.api_key.id]);
    expect((await h.call("GET", "/v1/users", { token: other.key })).status).toBe(401);
    expect((await h.call("GET", "/v1/api-keys", { token: admin })).body.data.find((k: { id: string }) => k.id === other.api_key.id).status).toBe("expired");

    expect((await h.call("DELETE", `/v1/api-keys/${keyId}`, { token: admin })).status).toBe(204);
    expect((await h.call("GET", "/v1/users", { token: key })).status).toBe(401);
    const ev = (await h.call("GET", "/v1/audit/events?type=api_key.revoked", { token: admin })).body.data[0];
    expect(ev.target.display).toBe("HR offboarding");
  });
});

import { generateKeyPairSync } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** What Nexus Mobile's "My requests" and "Ask for access" rely on, from a phone's session. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let root = "";
let phone = "";
let catalogId = "";

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  root = (await h.call("POST", "/v1/signup", { body: { organization_name: "Phone Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: root, body: { mfa_policy: "off" } });
  const email = uniqueEmail("ana");
  await h.call("POST", "/v1/users", { token: root, body: { email, given_name: "Ana", password: PASSWORD } });
  const web = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
  const code = (await h.call("POST", "/v1/me/factors/push/pairing", { token: web })).body.code;
  const pk = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
  phone = (await h.call("POST", "/v1/devices/pair", { body: { code, public_key: pk, device_name: "Ana's phone", platform: "android" } })).body.token;
  const app = (await h.call("POST", "/v1/apps", { token: root, body: { protocol: "oidc", name: "Figma", redirect_uris: ["https://figma.example.com/cb"] } })).body.app;
  const cat = await h.call("POST", "/v1/access/catalog", { token: root, body: { resource_type: "app", resource_id: app.id, max_hours: 24, stages: [{ kind: "role", role: "owner" }] } });
  expect(cat.status, JSON.stringify(cat.body)).toBe(201);
  catalogId = cat.body.data.find((i: any) => i.resource_id === app.id).id;
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("requests from Nexus Mobile", () => {
  it("lists what can be asked for, asks, and follows the decision", async () => {
    const item = (await h.call("GET", "/v1/access/catalog", { token: phone })).body.data.find((i: any) => i.id === catalogId);
    expect(item).toMatchObject({ name: "Figma", you: { eligible: false, has_access: false, open_request: null } }); // not pre-approved: approvers decide
    const r = await h.call("POST", "/v1/access/requests", { token: phone, body: { catalog_id: catalogId, justification: "Design review this week", duration_hours: 8 } });
    expect(r.status).toBe(201);
    let mine = (await h.call("GET", "/v1/access/requests?view=mine", { token: phone })).body.data;
    expect(mine[0]).toMatchObject({ status: "pending", stage: 0, stages: 1, approvers: [expect.stringContaining("root")] });

    await h.call("POST", `/v1/access/requests/${r.body.id}/decision`, { token: root, body: { decision: "approve", comment: "" } });
    mine = (await h.call("GET", "/v1/access/requests?view=mine", { token: phone })).body.data;
    expect(mine[0]).toMatchObject({ status: "active", expires_at: expect.any(String) });
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=10&filter=all", { token: phone })).body.data;
    expect(inbox.map((n: any) => n.category)).toContain("access.granted"); // what opens My requests on the phone
  });

  it("gives access back from the phone without a fresh sign-in check", async () => {
    // The phone's sign-in check is an hour old.
    await db.query("UPDATE sessions SET mfa_at = now() - interval '1 hour' WHERE client = 'mobile' AND revoked_at IS NULL AND user_id = (SELECT id FROM users WHERE given_name = 'Ana' ORDER BY created_at DESC LIMIT 1)");
    const active = (await h.call("GET", "/v1/access/requests?view=mine&status=active", { token: phone })).body.data[0];
    const back = await h.call("POST", `/v1/access/requests/${active.id}/revoke`, { token: phone, body: { reason: "Given back from Nexus Mobile" } });
    expect(back.status, JSON.stringify(back.body)).toBe(200);
    expect(back.body).toMatchObject({ status: "revoked", end_reason: "Given back from Nexus Mobile" });
  });

  it("withdraws a pending request", async () => {
    const r = await h.call("POST", "/v1/access/requests", { token: phone, body: { catalog_id: catalogId, justification: "Changed my mind later", duration_hours: 1 } });
    expect((await h.call("POST", `/v1/access/requests/${r.body.id}/cancel`, { token: phone })).body.status).toBe("canceled");
  });
});

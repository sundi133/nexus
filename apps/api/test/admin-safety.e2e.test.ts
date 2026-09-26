import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadLocal } from "../src/directory/sync/service.js";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";
import { SoftAuthenticator } from "./webauthn.js";

/** Admin safety: owners confirm with passkeys (RBAC-04), break-glass accounts (RBAC-05), undo settings changes (OPS-06). */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let orgId = "";
const root = { email: uniqueEmail("root"), token: "", secret: "" };
const key = new SoftAuthenticator();

const stepUpTotp = (token: string, offset: number) => h.call("POST", "/v1/auth/mfa/totp", { token, body: { code: totpCode(root.secret, offset) } });
async function stepUpPasskey(token: string) {
  const opts = await h.call("POST", "/v1/auth/mfa/webauthn/options", { token, body: {} });
  const r = await h.call("POST", "/v1/auth/mfa/webauthn", { token, body: { challenge_id: opts.body.challenge_id, response: key.authenticate(opts.body.options) } });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
}

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  root.token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Safe Co", email: root.email, password: PASSWORD, given_name: "Root" } })).body.token;
  orgId = (await h.call("GET", "/v1/me", { token: root.token })).body.organization.id;
  const f = await h.call("POST", "/v1/me/factors/totp", { token: root.token, body: {} });
  root.secret = f.body.secret;
  await h.call("POST", `/v1/me/factors/${f.body.id}/verify`, { token: root.token, body: { code: totpCode(root.secret) } });
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("owners confirm admin actions with a passkey", () => {
  it("is part of the secure baseline", async () => {
    const b = (await h.call("GET", "/v1/org/baseline", { token: root.token })).body;
    expect(b.items.find((i: { id: string }) => i.id === "owner_passkeys")).toMatchObject({ compliant: false, auto_apply: true, impact: expect.stringContaining("1 owner has no passkey") });
    expect(b.items.find((i: { id: string }) => i.id === "break_glass")).toMatchObject({ compliant: false, auto_apply: false });
    const r = await h.call("POST", "/v1/org/baseline/apply", { token: root.token, body: {} });
    expect(r.body.applied).toContain("owners_require_passkey");
  });

  it("refuses other methods for owners' admin actions, but not for personal ones", async () => {
    await stepUpTotp(root.token, 1);
    const r = await h.call("PATCH", "/v1/org/settings", { token: root.token, body: { session_ttl_hours: 8 } });
    expect(r).toMatchObject({ status: 401, body: { code: "passkey_required" } });
    // Personal: still fine with a TOTP code, so the owner can go add a passkey.
    expect((await h.call("POST", "/v1/me/recovery-codes", { token: root.token, body: {} })).status).toBe(201);
    const opts = await h.call("POST", "/v1/me/factors/webauthn/options", { token: root.token });
    expect((await h.call("POST", "/v1/me/factors/webauthn", { token: root.token, body: { challenge_id: opts.body.challenge_id, name: "YubiKey", response: key.register(opts.body.options) } })).status).toBe(201);
  });

  it("accepts a passkey step-up", async () => {
    await stepUpPasskey(root.token);
    expect((await h.call("PATCH", "/v1/org/settings", { token: root.token, body: { session_ttl_hours: 8 } })).status).toBe(200);
  });

  it("doesn't affect other admins", async () => {
    const email = uniqueEmail("adm");
    await h.call("POST", "/v1/users", { token: root.token, body: { email, given_name: "Adm", password: PASSWORD, roles: ["admin"] } });
    const adm = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token; // enroll_mfa (MFA is required for everyone now)
    const f = await h.call("POST", "/v1/me/factors/totp", { token: adm, body: {} });
    await h.call("POST", `/v1/me/factors/${f.body.id}/verify`, { token: adm, body: { code: totpCode(f.body.secret) } });
    // An admin (not an owner) confirms with TOTP as before.
    expect((await h.call("PATCH", "/v1/org/settings", { token: adm, body: { session_ttl_hours: 10 } })).status).toBe(200);
  });
});

describe("undo a settings change", () => {
  const changes = async () => (await h.call("GET", "/v1/audit/events?type=org.settings_updated", { token: root.token })).body.data as { id: string; details: { changes: Record<string, { from: unknown; to: unknown }>; via: string } }[];

  it("restores the previous values, and says when a later change is in the way", async () => {
    await stepUpPasskey(root.token);
    await h.call("PATCH", "/v1/org/settings", { token: root.token, body: { session_ttl_hours: 6 } });
    const [latest, earlier] = await changes();
    expect(latest!.details.changes.session_ttl_hours).toEqual({ from: 10, to: 6 });
    // The earlier change (8 → 10) is blocked by the later one.
    expect((await h.call("POST", "/v1/org/settings/revert", { token: root.token, body: { event_id: earlier!.id } })).body.code).toBe("changed_since");

    const r = await h.call("POST", "/v1/org/settings/revert", { token: root.token, body: { event_id: latest!.id } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.session_ttl_hours).toBe(10);
    const [undo] = await changes();
    expect(undo!.details).toMatchObject({ changes: { session_ttl_hours: { from: 6, to: 10 } }, via: `undo:${latest!.id}` });
  });
});

describe("break-glass accounts", () => {
  const bg = { email: uniqueEmail("emergency"), id: "", password: "" };
  const bgKey = new SoftAuthenticator(); // break-glass accounts should use a hardware key kept with the sealed password

  it("must be owners, and get a sealed emergency password", async () => {
    bg.id = (await h.call("POST", "/v1/users", { token: root.token, body: { email: bg.email, given_name: "Emergency", password: PASSWORD } })).body.id;
    await stepUpPasskey(root.token);
    expect((await h.call("PUT", `/v1/users/${bg.id}/break-glass`, { token: root.token, body: { enabled: true } })).body.code).toBe("not_owner");
    await h.call("PUT", `/v1/users/${bg.id}/roles`, { token: root.token, body: { roles: ["owner"] } });
    expect((await h.call("PUT", `/v1/users/${bg.id}/break-glass`, { token: root.token, body: { enabled: true } })).body).toEqual({ break_glass: true });
    const pw = await h.call("POST", `/v1/users/${bg.id}/break-glass/password`, { token: root.token, body: {} });
    expect(pw.status).toBe(201);
    bg.password = pw.body.password;
    expect(bg.password).toMatch(/^([A-HJ-NP-Z2-9]{5}-){5}[A-HJ-NP-Z2-9]{5}$/);
    expect((await h.call("GET", `/v1/users/${bg.id}`, { token: root.token })).body.break_glass).toBe(true);
    const b = (await h.call("GET", "/v1/org/baseline", { token: root.token })).body;
    expect(b.items.find((i: { id: string }) => i.id === "break_glass").compliant).toBe(true);
  });

  it("alerts every admin when used", async () => {
    const r = await h.call("POST", "/v1/auth/login", { body: { email: bg.email, password: bg.password } });
    expect(r.status).toBe(200);
    // First use: set up its hardware key.
    const opts = await h.call("POST", "/v1/me/factors/webauthn/options", { token: r.body.token });
    expect((await h.call("POST", "/v1/me/factors/webauthn", { token: r.body.token, body: { challenge_id: opts.body.challenge_id, name: "Sealed key", response: bgKey.register(opts.body.options) } })).status).toBe(201);
    const inbox = await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: root.token });
    expect(inbox.body.data[0]).toMatchObject({ title: `Break-glass account ${bg.email} was used`, severity: "critical" });
    const ev = (await h.call("GET", "/v1/audit/events?type=auth.break_glass_used", { token: root.token })).body.data[0];
    expect(ev).toMatchObject({ actor: { display: bg.email }, details: { method: "its password" } });
  });

  it("can't be locked out by a directory sync, or offboarded while designated", async () => {
    const local = await h.deps.db.tenant(orgId, (tx) => loadLocal(tx, "00000000-0000-0000-0000-000000000000"));
    expect(local.users.some((u) => u.id === bg.id)).toBe(false); // invisible to syncs, so never suspended
    await stepUpPasskey(root.token);
    expect((await h.call("POST", `/v1/users/${bg.id}/offboard`, { token: root.token, body: {} })).body.code).toBe("break_glass");
  });

  it("isn't subject to conditional access", async () => {
    const app = (await h.call("POST", "/v1/apps", { token: root.token, body: { protocol: "oidc", name: "Console mirror", redirect_uris: ["https://mirror.example.com/cb"] } })).body.app;
    await h.call("POST", `/v1/apps/${app.id}/assignments`, { token: root.token, body: { principals: [{ type: "user", id: bg.id }] } });
    await stepUpPasskey(root.token);
    await h.call("POST", "/v1/access-policies", { token: root.token, body: { name: "Block everything", mode: "enforce", requirement: "block", conditions: { apps: "all", users: { include: "all", exclude: { groups: [], users: [] } } } } });
    const slug = (await h.call("GET", "/v1/me", { token: root.token })).body.organization.slug;
    const o = await h.call("POST", "/v1/auth/passkey/options", { body: { email: bg.email } });
    const bgSession = (await h.call("POST", "/v1/auth/passkey", { body: { email: bg.email, challenge_id: o.body.challenge_id, response: bgKey.authenticate(o.body.options) } })).body.token;
    const inbox = await h.call("GET", "/v1/me/notifications?limit=1&filter=all", { token: root.token });
    expect(inbox.body.data[0].title).toBe(`Break-glass account ${bg.email} was used`); // passkey sign-ins alert too
    const q = new URLSearchParams({ client_id: app.oidc.client_id, redirect_uri: "https://mirror.example.com/cb", response_type: "code", scope: "openid", state: "s", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
    const d = await h.call("GET", `/v1/sso/oidc/${slug}/authorize?${q}`, { token: bgSession });
    expect(d.body.action).toBe("redirect");
  });
});

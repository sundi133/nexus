import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";
import { SoftAuthenticator } from "./webauthn.js";

/** Signing in with a managed device: the agent's attestation plus a passkey bound to that device. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let ana = { email: "", id: "", token: "" };
let bob = { email: "", id: "" };
const mac = new SoftDevice();
const shared = new SoftDevice();
const touchId = new SoftAuthenticator();
const other = new SoftAuthenticator();
let origin = "";

async function enroll(d: SoftDevice, token: string, hostname: string, mine: boolean) {
  await d.init();
  const t = mine ? (await h.call("POST", "/v1/me/devices/enrollment-token", { token })).body.token : (await h.call("POST", "/v1/devices/enrollment-tokens", { token, body: { name: "t" } })).body.token;
  const body = JSON.stringify({ token: t, device: { hostname, platform: "macos", os_version: "15.0" } });
  const r = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof("/v1/agent/enroll", body, { enroll: true })}` }, body });
  d.id = ((await r.json()) as { device_id: string }).device_id;
}
/** The sign-in page's steps: a nonce, the local agent's attestation, then the passkey request. */
async function begin(d: SoftDevice, opts: { origin?: string; nonce?: string } = {}) {
  const s = (await h.call("POST", "/v1/auth/device/start")).body;
  return h.call("POST", "/v1/auth/device/options", { body: { ticket: s.ticket, attestation: await d.attest(opts.nonce ?? s.nonce, opts.origin ?? origin) } });
}

beforeAll(async () => {
  h = await bootApp();
  origin = h.deps.cfg.publicUrl;
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Go Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  ana.email = uniqueEmail("ana");
  ana.id = (await h.call("POST", "/v1/users", { token: admin, body: { email: ana.email, given_name: "Ana", family_name: "Lima", password: PASSWORD } })).body.id;
  ana.token = (await h.call("POST", "/v1/auth/login", { body: { email: ana.email, password: PASSWORD } })).body.token;
  bob.email = uniqueEmail("bob");
  bob.id = (await h.call("POST", "/v1/users", { token: admin, body: { email: bob.email, given_name: "Bob", password: PASSWORD } })).body.id;
  await enroll(mac, ana.token, "ana-mbp", true);
  await enroll(shared, admin, "front-desk", false);
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("device sign-in", () => {
  let factorId = "";

  it("isn't available until it's set up on the device", async () => {
    expect((await begin(mac)).body.code).toBe("not_set_up");
    expect((await begin(shared)).body.code).toBe("device_unassigned");
  });

  it("is set up from a session that verified the device, with a passkey made on it", async () => {
    const o = await h.call("POST", "/v1/me/factors/webauthn/options", { token: ana.token });
    const f = await h.call("POST", "/v1/me/factors/webauthn", { token: ana.token, body: { challenge_id: o.body.challenge_id, name: "Touch ID", response: touchId.register(o.body.options) } });
    expect(f.status).toBe(201);
    factorId = f.body.id;
    expect((await h.call("POST", "/v1/me/device-sign-in", { token: ana.token, body: { factor_id: factorId } })).body.code).toBe("device_not_verified");

    const ch = (await h.call("POST", "/v1/me/device-trust/challenge", { token: ana.token })).body;
    expect((await h.call("POST", "/v1/me/device-trust", { token: ana.token, body: { challenge_id: ch.challenge_id, attestation: await mac.attest(ch.nonce, origin) } })).status).toBe(200);
    const bound = await h.call("POST", "/v1/me/device-sign-in", { token: ana.token, body: { factor_id: factorId } });
    expect(bound.body).toMatchObject({ factor_id: factorId, device: { hostname: "ana-mbp" } });
    expect((await h.call("GET", "/v1/me/device-sign-in", { token: ana.token })).body).toMatchObject({ data: [{ factor_id: factorId }], this_device: { hostname: "ana-mbp" } });
  });

  it("signs the device's user in with no email or password, on a verified device", async () => {
    const o = await begin(mac);
    expect(o.status).toBe(200);
    expect(o.body).toMatchObject({ user: { name: "Ana Lima", email: ana.email }, device: { hostname: "ana-mbp" } });
    const r = await h.call("POST", "/v1/auth/device", { body: { ticket: o.body.ticket, response: touchId.authenticate(o.body.options) } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((await h.call("GET", "/v1/me", { token: r.body.token })).body.user.email).toBe(ana.email);
    const s = (await db.query("SELECT device_id, device_verified_at, mfa_method FROM sessions WHERE id = $1", [r.body.session.id])).rows[0];
    expect(s).toMatchObject({ device_id: mac.id, mfa_method: "webauthn" });
    expect(s.device_verified_at).toBeInstanceOf(Date);
    // The passkey request is single use.
    expect((await h.call("POST", "/v1/auth/device", { body: { ticket: o.body.ticket, response: touchId.authenticate(o.body.options) } })).status).toBeGreaterThanOrEqual(400);
  });

  it("refuses attestations for another site or another sign-in", async () => {
    expect((await begin(mac, { origin: "https://evil.example" })).body.code).toBe("invalid_attestation");
    expect((await begin(mac, { nonce: "not-the-nonce" })).body.code).toBe("invalid_attestation");
    expect((await h.call("POST", "/v1/auth/device/options", { body: { ticket: "forged", attestation: await mac.attest("x", origin) } })).body.code).toBe("ticket_expired");
  });

  it("only accepts the passkey bound to that device", async () => {
    const o = await h.call("POST", "/v1/me/factors/webauthn/options", { token: ana.token });
    await h.call("POST", "/v1/me/factors/webauthn", { token: ana.token, body: { challenge_id: o.body.challenge_id, name: "YubiKey", response: other.register(o.body.options) } });
    const opts = await begin(mac);
    expect(opts.body.options.allowCredentials).toHaveLength(1); // the bound one only
    expect((await h.call("POST", "/v1/auth/device", { body: { ticket: opts.body.ticket, response: other.authenticate(opts.body.options) } })).body.code).toBe("passkey_invalid");
  });

  it("stops when the device isn't compliant, or is given to someone else", async () => {
    await db.query("UPDATE devices SET compliance = 'non_compliant' WHERE id = $1", [mac.id]);
    expect((await begin(mac)).body.code).toBe("device_non_compliant");
    await db.query("UPDATE devices SET compliance = 'compliant' WHERE id = $1", [mac.id]);

    const opts = await begin(mac);
    await db.query("UPDATE devices SET primary_user_id = $1 WHERE id = $2", [bob.id, mac.id]); // reassigned mid-sign-in
    expect((await h.call("POST", "/v1/auth/device", { body: { ticket: opts.body.ticket, response: touchId.authenticate(opts.body.options) } })).body.code).toBe("passkey_invalid");
    expect((await begin(mac)).body.code).toBe("not_set_up"); // Bob has no passkey bound to it
    const fails = (await db.query("SELECT details->>'reason' AS r FROM audit_events WHERE type = 'auth.login' AND outcome = 'failure' AND actor_id = $1", [ana.id])).rows.map((x) => x.r);
    expect(fails).toEqual(expect.arrayContaining(["device_mismatch"]));
  });

  it("can be turned off, leaving the passkey", async () => {
    expect((await h.call("DELETE", `/v1/me/device-sign-in/${factorId}`, { token: ana.token })).status).toBe(204);
    expect((await h.call("GET", "/v1/me/device-sign-in", { token: ana.token })).body.data).toEqual([]);
    expect((await db.query("SELECT count(*)::int AS n FROM auth_factors WHERE id = $1", [factorId])).rows[0].n).toBe(1);
  });
});

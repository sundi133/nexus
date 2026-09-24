import { createHash, randomBytes } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/**
 * Conditional access end to end: policies decide OIDC sign-ins, sessions
 * prove which device they're on through the local agent's attestation, and
 * every decision is explained and audited.
 */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client; // owner-role connection, only to simulate time passing
let admin = "";
let slug = "";
let bobId = "";
let bob = "";
let bobEmail = "";
let fresh = ""; // a second session of Bob's, never bound to a device
let appId = "";
let clientId = "";
const WEB = "http://localhost:3100";
const REDIRECT = "https://wiki.example.com/oauth/callback";
const laptop = new SoftDevice();

const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 300 }, system_integrity: { status: "on" } };

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
async function checkin(posture: unknown) {
  const payload = { device: { agent_version: "0.1.0" }, posture, inventory: {} };
  return agentCall("/v1/agent/checkin", payload, await laptop.proof("/v1/agent/checkin", JSON.stringify(payload)));
}

/** What the console's /oidc/{slug}/authorize route does with the user's session. */
async function signIn(token: string, extra: Record<string, string> = {}) {
  const q = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: "code",
    scope: "openid email",
    state: "st",
    code_challenge: createHash("sha256").update(randomBytes(32).toString("base64url")).digest("base64url"),
    code_challenge_method: "S256",
    ...extra,
  });
  const r = await h.call("GET", `/v1/sso/oidc/${slug}/authorize?${q}`, { token });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  return r.body as { action: string; location?: string; reason?: string; code?: string; title?: string; message?: string; app_name?: string };
}

/** The browser half of the handshake: challenge → agent signs → submit. */
async function proveDevice(token: string, device = laptop, origin = WEB) {
  const ch = await h.call("POST", "/v1/me/device-trust/challenge", { token, body: {} });
  expect(ch.status).toBe(201);
  expect(ch.body.agent_url).toBe("http://127.0.0.1:47823");
  return h.call("POST", "/v1/me/device-trust", { token, body: { challenge_id: ch.body.challenge_id, attestation: await device.attest(ch.body.nonce, origin) } });
}

let policyId = "";
async function setPolicy(body: Record<string, unknown>) {
  const r = policyId
    ? await h.call("PUT", `/v1/access-policies/${policyId}`, { token: admin, body })
    : await h.call("POST", "/v1/access-policies", { token: admin, body });
  expect([200, 201], JSON.stringify(r.body)).toContain(r.status);
  policyId = r.body.data.find((p: { name: string }) => p.name === body.name).id;
  return r.body.data as Record<string, any>[];
}
const policy = (over: Record<string, unknown> = {}) => ({
  name: "Wiki needs a healthy laptop",
  mode: "enforce",
  requirement: "require_compliant_device",
  conditions: { apps: [appId], users: { include: "all", exclude: { groups: [], users: [] } } },
  ...over,
});

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Hooli", email: uniqueEmail("gavin"), password: PASSWORD, given_name: "Gavin" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  slug = (await h.call("GET", "/v1/me", { token: admin })).body.organization.slug;
  bobEmail = uniqueEmail("bob");
  bobId = (await h.call("POST", "/v1/users", { token: admin, body: { email: bobEmail, given_name: "Bob", password: PASSWORD } })).body.id;
  bob = (await h.call("POST", "/v1/auth/login", { body: { email: bobEmail, password: PASSWORD } })).body.token;
  fresh = (await h.call("POST", "/v1/auth/login", { body: { email: bobEmail, password: PASSWORD } })).body.token;

  const app = await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "oidc", name: "Team Wiki", redirect_uris: [REDIRECT] } });
  appId = app.body.app.id;
  clientId = app.body.app.oidc.client_id;
  await h.call("POST", `/v1/apps/${appId}/assignments`, { token: admin, body: { principals: [{ type: "user", id: bobId }] } });

  // Bob enrolls his own laptop.
  const t = (await h.call("POST", "/v1/me/devices/enrollment-token", { token: bob, body: {} })).body.token;
  await laptop.init();
  const payload = { token: t, device: { hostname: "bobs-mbp", platform: "macos", os_name: "macOS", os_version: "15.1", os_build: "24B83", arch: "arm64", model: "Mac", serial: "X", agent_version: "0.1.0" } };
  const e = await agentCall("/v1/agent/enroll", payload, await laptop.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  expect(e.status).toBe(201);
  expect(e.body.web_origin).toBe(WEB); // the only origin the agent will attest to
  laptop.id = e.body.device_id;
  expect((await checkin(healthy)).body).toMatchObject({ compliance: "compliant", web_origin: WEB });
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("conditional access", () => {
  it("allows sign-in when no policy applies", async () => {
    expect((await signIn(bob)).action).toBe("redirect");
  });

  it("only admins manage policies", async () => {
    const r = await h.call("POST", "/v1/access-policies", { token: bob, body: policy() });
    expect(r.status).toBe(403);
    const empty = await h.call("POST", "/v1/access-policies", { token: admin, body: { ...policy(), conditions: { apps: "all", users: { include: { groups: [], users: [] } } } } });
    expect(empty.status).toBe(400); // "include nobody" is a mistake, not a policy
  });

  it("asks the browser to prove its device when a device policy is enforced", async () => {
    const list = await setPolicy(policy());
    expect(list[0]).toMatchObject({ mode: "enforce", impact_7d: { would_block: 0, blocked: 0 } });
    const d = await signIn(bob);
    expect(d).toMatchObject({ action: "device_check", app_name: "Team Wiki" });
    expect(d.reason).toContain("compliant device");
    // Silent sign-in can't show a device check.
    const silent = await signIn(bob, { prompt: "none" });
    expect(new URL(silent.location!).searchParams.get("error")).toBe("interaction_required");
  });

  it("binds the session to the laptop after a valid attestation, then lets it in", async () => {
    const v = await proveDevice(bob);
    expect(v.status, JSON.stringify(v.body)).toBe(200);
    expect(v.body).toMatchObject({ id: laptop.id, hostname: "bobs-mbp", compliance: "compliant" });
    expect((await signIn(bob)).action).toBe("redirect");
    const audit = await h.call("GET", "/v1/audit/events?type=sso.login", { token: admin });
    expect(audit.body.data[0].details.policies[0]).toMatchObject({ policy: "Wiki needs a healthy laptop", satisfied: true, reason: "bobs-mbp is compliant" });
    const trust = await h.call("GET", "/v1/audit/events?type=device.trust_verified", { token: admin });
    expect(trust.body.data[0]).toMatchObject({ target: { display: "bobs-mbp" }, actor: { display: bobEmail } });
  });

  it("asks again once the device proof is 12 hours old", async () => {
    await owner.query("UPDATE sessions SET device_verified_at = now() - interval '13 hours' WHERE device_id = $1", [laptop.id]);
    expect((await signIn(bob)).action).toBe("device_check");
    expect((await proveDevice(bob)).status).toBe(200);
    expect((await signIn(bob)).action).toBe("redirect");
  });

  it("blocks a non-compliant device and says exactly what to fix", async () => {
    expect((await checkin({ ...healthy, firewall: { status: "off" } })).body.compliance).toBe("non_compliant");
    const d = await signIn(bob);
    expect(d).toMatchObject({ action: "error", code: "access_denied", title: "Access to Team Wiki is blocked" });
    expect(d.message).toContain("bobs-mbp isn't compliant");
    expect(d.message).toMatch(/firewall/i);
    const denied = await h.call("GET", "/v1/audit/events?type=sso.login", { token: admin });
    expect(denied.body.data[0]).toMatchObject({ outcome: "denied", details: { reason: "access_policy" } });
    const list = await h.call("GET", "/v1/access-policies", { token: admin });
    expect(list.body.data[0].impact_7d.blocked).toBe(1);
  });

  it("report-only lets people in but records who would have been blocked", async () => {
    await setPolicy(policy({ mode: "report_only" }));
    expect((await signIn(bob)).action).toBe("redirect");
    const wb = await h.call("GET", "/v1/audit/events?type=access.would_block", { token: admin });
    expect(wb.body.data[0]).toMatchObject({ outcome: "denied", target: { display: "Team Wiki" }, details: { policy_id: policyId } });
    const list = await h.call("GET", "/v1/access-policies", { token: admin });
    expect(list.body.data[0].impact_7d.would_block).toBe(1);
  });

  it("exclusions win over inclusion", async () => {
    await setPolicy(policy({ conditions: { apps: [appId], users: { include: "all", exclude: { groups: [], users: [bobId] } } } }));
    expect((await signIn(bob)).action).toBe("redirect");
  });

  it("explains a what-if without touching real sign-ins", async () => {
    await setPolicy(policy({ mode: "report_only" }));
    const noDevice = await h.call("POST", "/v1/access-policies/simulate", { token: admin, body: { user_id: bobId, app_id: appId, mfa: false, device_id: null } });
    expect(noDevice.body).toMatchObject({ outcome: "needs_device" });
    const onLaptop = await h.call("POST", "/v1/access-policies/simulate", { token: admin, body: { user_id: bobId, app_id: appId, mfa: false, device_id: laptop.id } });
    expect(onLaptop.body.outcome).toBe("block");
    expect(onLaptop.body.results[0]).toMatchObject({ mode: "report_only", matched: true, satisfied: false }); // shown as if enforced, labelled with its real mode
    await checkin(healthy);
  });

  it("requires MFA and accepts a step-up", async () => {
    await setPolicy(policy({ requirement: "require_mfa", mode: "enforce" }));
    expect(await signIn(bob)).toMatchObject({ action: "mfa", reason: "This app requires multi-factor authentication" });
    const start = await h.call("POST", "/v1/me/factors/totp", { token: bob, body: {} });
    await h.call("POST", `/v1/me/factors/${start.body.id}/verify`, { token: bob, body: { code: totpCode(start.body.secret) } });
    await h.call("POST", "/v1/auth/mfa/totp", { token: bob, body: { code: totpCode(start.body.secret, 1) } });
    expect((await signIn(bob)).action).toBe("redirect");
  });

  it("blocks outright", async () => {
    await setPolicy(policy({ requirement: "block" }));
    expect(await signIn(bob)).toMatchObject({ action: "error", code: "access_denied", message: "Access to this app is blocked by policy" });
    expect((await h.call("DELETE", `/v1/access-policies/${policyId}`, { token: admin })).status).toBe(200);
    expect((await signIn(bob)).action).toBe("redirect");
  });
});

describe("device attestation is hard to forge", () => {

  it("refuses an attestation made for another web origin", async () => {
    const r = await proveDevice(fresh, laptop, "https://evil.example.com");
    expect(r.status).toBe(400);
    expect(r.body.title).toContain("evil.example.com");
  });

  it("refuses a key that isn't the device's", async () => {
    const impostor = await new SoftDevice().init();
    impostor.id = laptop.id; // claims to be the laptop, signs with its own key
    expect((await proveDevice(fresh, impostor)).status).toBe(400);
  });

  it("refuses a replayed or foreign challenge", async () => {
    const ch = await h.call("POST", "/v1/me/device-trust/challenge", { token: fresh, body: {} });
    const attestation = await laptop.attest(ch.body.nonce, WEB);
    // Another session can't redeem it.
    expect((await h.call("POST", "/v1/me/device-trust", { token: admin, body: { challenge_id: ch.body.challenge_id, attestation } })).status).toBe(400);
    expect((await h.call("POST", "/v1/me/device-trust", { token: fresh, body: { challenge_id: ch.body.challenge_id, attestation } })).status).toBe(200);
    expect((await h.call("POST", "/v1/me/device-trust", { token: fresh, body: { challenge_id: ch.body.challenge_id, attestation } })).status).toBe(400);
  });

  it("refuses a signature over a different nonce, or a stale one", async () => {
    const ch = await h.call("POST", "/v1/me/device-trust/challenge", { token: fresh, body: {} });
    const wrong = await laptop.attest("not-the-nonce", WEB);
    expect((await h.call("POST", "/v1/me/device-trust", { token: fresh, body: { challenge_id: ch.body.challenge_id, attestation: wrong } })).status).toBe(400);
    const ch2 = await h.call("POST", "/v1/me/device-trust/challenge", { token: fresh, body: {} });
    const old = await laptop.attest(ch2.body.nonce, WEB, { iatOffset: -600 });
    expect((await h.call("POST", "/v1/me/device-trust", { token: fresh, body: { challenge_id: ch2.body.challenge_id, attestation: old } })).status).toBe(400);
  });

  it("refuses someone else's personal device", async () => {
    const r = await proveDevice(admin);
    expect(r.status).toBe(400);
    expect(r.body.title).toContain("assigned to someone else");
  });
});

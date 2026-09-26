import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FakeScim, TOKEN } from "./fake-scim.js";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** One-click offboarding (DIR-06): preview, do it (or schedule it), and prove every kind of access is gone. */

const fake = new FakeScim();
let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";
let chatId = "";
let wikiId = "";
let groupId = "";
let leaver = { id: "", email: "", token: "" };
let laptopId = "";

const run = async () => {
  await owner.query("UPDATE jobs SET run_at = now() WHERE org_id = $1 AND status = 'queued' AND kind <> 'user.offboard'", [orgId]);
  await h.jobs.runOnce({ orgId });
};

beforeAll(async () => {
  const base = await fake.start();
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Vandelay", email: uniqueEmail("art"), password: PASSWORD, given_name: "Art" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;

  // The leaver: an admin with MFA, in a group, with two apps (one provisioned) and a laptop.
  leaver.email = uniqueEmail("george");
  leaver.id = (await h.call("POST", "/v1/users", { token: admin, body: { email: leaver.email, given_name: "George", password: PASSWORD, roles: ["helpdesk"] } })).body.id;
  leaver.token = (await h.call("POST", "/v1/auth/login", { body: { email: leaver.email, password: PASSWORD } })).body.token;
  const f = await h.call("POST", "/v1/me/factors/totp", { token: leaver.token, body: {} });
  await h.call("POST", `/v1/me/factors/${f.body.id}/verify`, { token: leaver.token, body: { code: totpCode(f.body.secret) } });

  groupId = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "Sales" } })).body.id;
  await h.call("POST", `/v1/groups/${groupId}/members`, { token: admin, body: { user_ids: [leaver.id] } });
  chatId = (await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "oidc", name: "Chat", redirect_uris: ["https://chat.example.com/cb"] } })).body.app.id;
  wikiId = (await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "oidc", name: "Wiki", redirect_uris: ["https://wiki.example.com/cb"] } })).body.app.id;
  await h.call("POST", `/v1/apps/${chatId}/assignments`, { token: admin, body: { principals: [{ type: "group", id: groupId }] } });
  await h.call("POST", `/v1/apps/${wikiId}/assignments`, { token: admin, body: { principals: [{ type: "user", id: leaver.id }] } });
  await h.call("PUT", `/v1/apps/${chatId}/provisioning`, { token: admin, body: { base_url: `${base}/scim/v2`, token: TOKEN, enabled: true } });
  await run();
  expect(fake.byEmail(leaver.email)).toMatchObject({ active: true });

  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "laptops" } })).body.token;
  const d = await new SoftDevice().init();
  const payload = JSON.stringify({ token: t, device: { hostname: "georges-mbp", platform: "macos" } });
  const res = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof("/v1/agent/enroll", payload, { enroll: true })}` }, body: payload });
  laptopId = ((await res.json()) as { device_id: string }).device_id;
  await h.call("PATCH", `/v1/devices/${laptopId}`, { token: admin, body: { primary_user_id: leaver.id } });
});
afterAll(async () => {
  fake.stop();
  await owner.end();
  await h.close();
});

describe("offboarding", () => {
  it("previews everything that will be removed", async () => {
    const r = await h.call("GET", `/v1/users/${leaver.id}/offboarding`, { token: admin });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body).toMatchObject({
      user: { email: leaver.email, status: "active", managed_by_directory: false },
      sessions: 1,
      admin_roles: ["helpdesk"],
      groups: [{ id: groupId, name: "Sales" }],
      apps: [
        { name: "Chat", provisioned: true, action: "deactivate" },
        { name: "Wiki", provisioned: false, action: "sign_in_only" },
      ],
      devices: [{ id: laptopId, hostname: "georges-mbp" }],
      factors: 1,
      scheduled: null,
    });
  });

  it("can be scheduled for a last day, and cancelled", async () => {
    const at = new Date(Date.now() + 7 * 86400_000).toISOString();
    const r = await h.call("POST", `/v1/users/${leaver.id}/offboard`, { token: admin, body: { at, reason: "Last day Friday" } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.scheduled).toEqual({ at, reason: "Last day Friday" });
    expect(r.body.user.status).toBe("active"); // nothing happens yet
    await h.jobs.runOnce({ orgId });
    expect((await h.call("GET", "/v1/me", { token: leaver.token })).status).toBe(200);
    const c = await h.call("DELETE", `/v1/users/${leaver.id}/offboarding`, { token: admin });
    expect(c.body.scheduled).toBeNull();
  });

  it("removes every kind of access in one step", async () => {
    const r = await h.call("POST", `/v1/users/${leaver.id}/offboard`, { token: admin, body: { reason: "Resigned" } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body).toMatchObject({ user: { status: "deprovisioned" }, sessions: 0, admin_roles: [], groups: [], devices: [], factors: 0 });
    expect((await h.call("GET", "/v1/me", { token: leaver.token })).status).toBe(401);
    expect((await h.call("POST", "/v1/auth/login", { body: { email: leaver.email, password: PASSWORD } })).status).toBe(401);

    await run();
    expect(fake.byEmail(leaver.email)).toMatchObject({ active: false }); // deactivated in the provisioned app
    const device = await h.call("GET", `/v1/devices/${laptopId}`, { token: admin });
    expect(device.body.primary_user).toBeNull();

    const audit = await h.call("GET", "/v1/audit/events?type=user.offboarded", { token: admin });
    expect(audit.body.data[0].details).toMatchObject({
      reason: "Resigned",
      effects: { sessions_revoked: 1, admin_roles_removed: ["helpdesk"], groups_removed: ["Sales"], app_accounts: ["Chat: deactivate"], sign_in_only_apps: ["Wiki"], factors_removed: 1, devices_unassigned: ["georges-mbp"] },
    });
    const inbox = await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin });
    expect(inbox.body.data[0].title).toBe("Collect georges-mbp from George");
  });

  it("is final", async () => {
    expect((await h.call("POST", `/v1/users/${leaver.id}/offboard`, { token: admin, body: {} })).body.code).toBe("already_offboarded");
    expect((await h.call("POST", `/v1/users/${leaver.id}/activate`, { token: admin, body: {} })).body.code).toBe("deprovisioned");
  });

  it("runs on schedule", async () => {
    const email = uniqueEmail("kramer");
    const id = (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Kramer", password: PASSWORD } })).body.id;
    await h.call("POST", `/v1/users/${id}/offboard`, { token: admin, body: { at: new Date(Date.now() + 3600_000).toISOString(), reason: "Contract ends" } });
    await owner.query("UPDATE jobs SET run_at = now() WHERE org_id = $1 AND kind = 'user.offboard'", [orgId]);
    await h.jobs.runOnce({ orgId });
    const u = await h.call("GET", `/v1/users/${id}/offboarding`, { token: admin });
    expect(u.body.user.status).toBe("deprovisioned");
    const audit = await h.call("GET", "/v1/audit/events?type=user.offboarded", { token: admin });
    expect(audit.body.data[0]).toMatchObject({ actor: { display: "Scheduled offboarding" }, target: { display: email } });
  });

  it("protects owners and yourself", async () => {
    const me = (await h.call("GET", "/v1/me", { token: admin })).body.user.id;
    expect((await h.call("POST", `/v1/users/${me}/offboard`, { token: admin, body: {} })).body.code).toBe("cannot_target_self");
  });
});

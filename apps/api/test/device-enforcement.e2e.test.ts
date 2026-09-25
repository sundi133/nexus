import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { enqueue } from "../src/platform/jobs.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Device policies in audit or enforce mode, with a grace period (DPOL-04). */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let sam = "";
let orgId = "";
const device = new SoftDevice();

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
const info = { hostname: "sams-mbp", platform: "macos", os_name: "macOS", os_version: "15.1", os_build: "24B83", arch: "arm64", model: "MacBookPro18,3", serial: "C02ENF", agent_version: "0.1.0" };
const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 300 }, system_integrity: { status: "on" } };
const firewallOff = { ...healthy, firewall: { status: "off" } };
async function checkin(posture: unknown) {
  const payload = { device: { agent_version: "0.1.0" }, posture };
  return agentCall("/v1/agent/checkin", payload, await device.proof("/v1/agent/checkin", JSON.stringify(payload)));
}
const detail = async () => (await h.call("GET", `/v1/devices/${device.id}`, { token: admin })).body;
const setPolicy = (body: Record<string, unknown>) => h.call("PUT", "/v1/device-policies/firewall", { token: admin, body: { enabled: true, params: {}, ...body } });
const samInbox = async () => (await h.call("GET", "/v1/me/notifications?limit=20&filter=all", { token: sam })).body.data as { title: string; category: string }[];

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Enforce Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  const email = uniqueEmail("sam");
  await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Sam", password: PASSWORD } });
  sam = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
  await device.init();
  const t = await h.call("POST", "/v1/me/devices/enrollment-token", { token: sam });
  const payload = { token: t.body.token, device: info };
  const r = await agentCall("/v1/agent/enroll", payload, await device.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  device.id = r.body.device_id;
  expect((await checkin(healthy)).body.compliance).toBe("compliant");
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("policy modes", () => {
  it("enforces by default, as before", async () => {
    const list = (await h.call("GET", "/v1/device-policies", { token: admin })).body.data;
    expect(list.find((p: any) => p.key === "firewall")).toMatchObject({ mode: "enforce", grace_hours: 0 });
    expect((await checkin(firewallOff)).body.compliance).toBe("non_compliant");
  });

  it("reports audited checks without counting them", async () => {
    const r = await setPolicy({ mode: "audit" });
    expect(r.body).toMatchObject({ reevaluated: { changed: 1 } });
    const d = await detail();
    expect(d.compliance).toBe("compliant");
    expect(d.checks.find((c: any) => c.key === "firewall")).toMatchObject({ status: "fail", enforced: false, grace_until: null });
    // Changing only the mode keeps the other settings.
    const ev = (await h.call("GET", "/v1/audit/events?type=device.policy_updated", { token: admin })).body.data[0];
    expect(ev.details).toMatchObject({ from: { mode: "enforce" }, to: { mode: "audit", grace_hours: 0 } });
  });
});

describe("grace periods", () => {
  it("keeps the device compliant while there's time, and tells its user once", async () => {
    await checkin(healthy);
    await setPolicy({ mode: "enforce", grace_hours: 72 });
    const r = await checkin(firewallOff);
    expect(r.body.compliance).toBe("compliant");
    const d = await detail();
    const due = new Date(d.compliance_grace_until).getTime() - Date.now();
    expect(due).toBeGreaterThan(71.9 * 3600_000);
    expect(due).toBeLessThan(72.1 * 3600_000);
    expect(d.checks.find((c: any) => c.key === "firewall")).toMatchObject({ status: "fail", enforced: true, grace_until: d.compliance_grace_until });
    await checkin(firewallOff); // still failing: no second message
    const msgs = (await samInbox()).filter((n) => n.category === "device.grace");
    expect(msgs).toHaveLength(1);
    expect(msgs[0]!.title).toMatch(/^Fix firewall on sams-mbp by .+ UTC$/);
  });

  it("counts the failure once the grace period is over, even if the device is offline", async () => {
    await owner.query("UPDATE device_checks SET failing_since = now() - interval '73 hours' WHERE device_id = $1 AND check_key = 'firewall'", [device.id]);
    await owner.query("UPDATE devices SET compliance_grace_until = now() - interval '1 hour' WHERE id = $1", [device.id]);
    const due = (await owner.query("SELECT device_id FROM nexus_devices_grace_expired()")).rows.map((r) => r.device_id);
    expect(due).toContain(device.id);
    // What the scheduler does for each: a re-evaluation job.
    await h.deps.db.tenant(orgId, (tx) => enqueue(tx, orgId, "device.reevaluate", { device_id: device.id }));
    await h.jobs.runOnce({ orgId });
    const d = await detail();
    expect(d).toMatchObject({ compliance: "non_compliant", compliance_grace_until: null });
    expect((await samInbox()).some((n) => n.title === "sams-mbp needs attention")).toBe(true);
  });

  it("resets when fixed", async () => {
    expect((await checkin(healthy)).body.compliance).toBe("compliant");
    expect((await detail()).checks.find((c: any) => c.key === "firewall")).toMatchObject({ status: "pass", grace_until: null });
    // A new failure starts a new grace period.
    await checkin(firewallOff);
    expect((await detail()).compliance_grace_until).not.toBeNull();
  });
});

import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Device settings the agent enforces (firewall, screen lock, BitLocker) and recovery-key escrow. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let helpdesk = "";
let readonly = "";
let orgId = "";
const device = new SoftDevice();
const KEY_A = "123456-234567-345678-456789-567890-678901-789012-890123";
const KEY_B = "111111-222222-333333-444444-555555-666666-777777-888888";

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
const info = { hostname: "win-laptop", platform: "windows", os_name: "Windows 11 Pro", os_version: "10.0.22631", os_build: "22631", arch: "amd64", model: "Latitude", serial: "WIN123", agent_version: "0.1.0" };
const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 300 }, system_integrity: { status: "on" } };
async function checkin(enforcement?: unknown) {
  const payload = { device: { agent_version: "0.1.0" }, posture: healthy, ...(enforcement ? { enforcement } : {}) };
  return agentCall("/v1/agent/checkin", payload, await device.proof("/v1/agent/checkin", JSON.stringify(payload)));
}
/** The signed policy's payload (signature checks are covered by the enforcement tests). */
const policyOf = (jws: string) => JSON.parse(Buffer.from(jws.split(".")[1]!, "base64url").toString()) as { ver: string; settings: Record<string, unknown> };
const setPolicy = (key: string, params: Record<string, unknown>) => h.call("PUT", `/v1/device-policies/${key}`, { token: admin, body: { enabled: true, params } });
const login = async (roles: string[]) => {
  const email = uniqueEmail(roles[0] ?? "user");
  await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "U", password: PASSWORD, roles } });
  return (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token as string;
};

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Settings Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  helpdesk = await login(["helpdesk"]);
  readonly = await login(["readonly"]);
  await device.init();
  const t = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "laptops" } });
  const payload = { token: t.body.token, device: info };
  device.id = (await agentCall("/v1/agent/enroll", payload, await device.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }))).body.device_id;
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("settings in the signed policy", () => {
  it("only escrows recovery keys by default: nothing on the device changes until an admin opts in", async () => {
    const r = await checkin();
    expect(policyOf(r.body.enforcement).settings).toEqual({ escrow_recovery_keys: true });
  });

  it("carries the settings an admin asked Nexus to fix, and a new version when they change", async () => {
    const before = policyOf((await checkin()).body.enforcement).ver;
    await setPolicy("firewall", { remediate: true });
    await setPolicy("screen_lock", { max_delay_minutes: 5, remediate: true });
    await setPolicy("disk_encryption", { remediate: true, escrow_recovery_keys: true });
    const p = policyOf((await checkin()).body.enforcement);
    expect(p.settings).toEqual({ firewall: true, screen_lock_minutes: 5, disk_encryption: true, escrow_recovery_keys: true });
    expect(p.ver).not.toBe(before);
    // A disabled policy isn't enforced, even with remediation on.
    await h.call("PUT", "/v1/device-policies/firewall", { token: admin, body: { enabled: false, params: { remediate: true } } });
    expect(policyOf((await checkin()).body.enforcement).settings).not.toHaveProperty("firewall");
    await setPolicy("firewall", { remediate: true });
  });

  it("is in sync once the agent reports the version", async () => {
    const p = policyOf((await checkin()).body.enforcement);
    await checkin({ version: p.ver, status: "0 app rules", events: [] });
    const s = (await h.call("GET", `/v1/devices/${device.id}/enforcement`, { token: admin })).body;
    expect(s).toMatchObject({ expected_version: p.ver, in_sync: true });
  });
});

describe("what the agent did", () => {
  it("shows each setting's outcome and audits changes once", async () => {
    const settings = [
      { key: "firewall", status: "applied", detail: "Windows Firewall turned on for all profiles" },
      { key: "screen_lock", status: "pending_restart", detail: "machine inactivity limit set to 5 min; applies after a restart" },
      { key: "disk_encryption", status: "compliant", detail: "" },
    ];
    await checkin({ version: "x", status: "", events: [], settings });
    await checkin({ version: "x", status: "", events: [], settings }); // the same again next check-in
    const d = (await h.call("GET", `/v1/devices/${device.id}`, { token: admin })).body;
    expect(d.settings.results).toEqual(settings);
    expect(d.settings.reported_at).not.toBeNull();
    const ev = (await db.query("SELECT details FROM audit_events WHERE org_id = $1 AND type = 'device.setting_applied' ORDER BY ts", [orgId])).rows.map((r) => r.details.setting);
    expect(ev).toEqual(["firewall", "screen_lock"]);
  });
});

describe("recovery key escrow", () => {
  it("seals the keys, and never puts them in the audit log", async () => {
    await checkin({ version: "x", status: "", events: [], recovery_keys: [{ volume: "C:", id: "{A}", password: KEY_A }] });
    const d = (await h.call("GET", `/v1/devices/${device.id}`, { token: admin })).body;
    expect(d.settings.recovery_keys).toBe(1);
    const stored = (await db.query("SELECT sealed FROM device_recovery_keys WHERE device_id = $1", [device.id])).rows[0].sealed as Buffer;
    expect(stored.toString("latin1")).not.toContain(KEY_A);
    const ev = (await db.query("SELECT details FROM audit_events WHERE org_id = $1 AND type = 'device.recovery_key_escrowed'", [orgId])).rows;
    expect(ev).toHaveLength(1);
    expect(JSON.stringify(ev)).not.toContain(KEY_A.slice(0, 13));
  });

  it("reveals them to help desk and admins only, and audits every reveal", async () => {
    expect((await h.call("GET", `/v1/devices/${device.id}/recovery-keys`, { token: readonly })).status).toBe(403);
    const r = await h.call("GET", `/v1/devices/${device.id}/recovery-keys`, { token: helpdesk });
    expect(r.status).toBe(200);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.body.data).toEqual([expect.objectContaining({ volume: "C:", key_id: "{A}", password: KEY_A, retired_at: null })]);
    const views = await db.query("SELECT actor_display FROM audit_events WHERE org_id = $1 AND type = 'device.recovery_key_viewed'", [orgId]);
    expect(views.rowCount).toBe(1);
  });

  it("keeps a rotated key, marked retired, for old backups", async () => {
    await checkin({ version: "x", status: "", events: [], recovery_keys: [{ volume: "C:", id: "{B}", password: KEY_B }] });
    const keys = (await h.call("GET", `/v1/devices/${device.id}/recovery-keys`, { token: admin })).body.data;
    expect(keys.map((k: any) => [k.key_id, k.retired_at === null])).toEqual([
      ["{B}", true],
      ["{A}", false],
    ]);
    expect((await h.call("GET", `/v1/devices/${device.id}`, { token: admin })).body.settings.recovery_keys).toBe(1);
  });

  it("refuses anything that isn't a BitLocker recovery password", async () => {
    await checkin({ version: "x", status: "", events: [], recovery_keys: [{ volume: "C:", id: "{C}", password: "not-a-key" }] });
    expect((await db.query("SELECT 1 FROM device_recovery_keys WHERE key_id = '{C}'")).rowCount).toBe(0);
  });
});

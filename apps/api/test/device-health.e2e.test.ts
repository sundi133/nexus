import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { evaluate } from "../src/alerts/engine.js";
import { lowestFree, markOffline } from "../src/devices/health.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Device health alerts: offline, disk nearly full, and compliance lost. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let orgId = "";
let d: SoftDevice;
let deviceId = "";
const GB = 1e9;
const meta = { ip: "", userAgent: "test", requestId: "" };

const posture = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
async function checkin(freeGb?: number, extra: Record<string, unknown> = {}) {
  const payload = { device: {}, posture, ...(freeGb === undefined ? {} : { inventory: { disks: [{ mount: "/System/Volumes/Data", size_bytes: 500 * GB, free_bytes: freeGb * GB }] } }), ...extra };
  const body = JSON.stringify(payload);
  const path = "/v1/agent/checkin";
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof(path, body)}` }, body });
  expect(res.status).toBe(200);
}
const events = async (type: string) => (await db.query("SELECT details FROM audit_events WHERE org_id = $1 AND type = $2 AND target_id = $3 ORDER BY ts, id", [orgId, type, deviceId])).rows.map((r) => r.details);
const alerts = async () => (await db.query("SELECT r.builtin_key FROM alerts a JOIN alert_rules r ON r.id = a.rule_id WHERE a.org_id = $1 ORDER BY a.created_at", [orgId])).rows.map((r) => r.builtin_key);

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Health Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "t" } })).body.token;
  d = await new SoftDevice().init();
  const body = JSON.stringify({ token: t, device: { hostname: "ana-mac", platform: "macos", os_version: "15.0" } });
  const r = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof("/v1/agent/enroll", body, { enroll: true })}` }, body });
  deviceId = d.id = ((await r.json()) as { device_id: string }).device_id;
  await evaluate(h.deps, orgId); // alerting follows the audit log from here
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("device health", () => {
  it("picks the fullest disk that reports free space", () => {
    expect(lowestFree([{ mount: "/", size_bytes: 100, free_bytes: 50 }, { mount: "/data", size_bytes: 200, free_bytes: 10 }, { mount: "/x", size_bytes: 10 }])).toEqual({ mount: "/data", free_percent: 5, free_gb: 0 });
    expect(lowestFree(undefined)).toBeNull();
  });

  it("reports a disk filling up once, and clears it once there's room again", async () => {
    await checkin(200); // 40% free
    await checkin(40); // 8%: under the 10% default
    await checkin(35);
    expect(await events("device.disk_low")).toEqual([{ mount: "/System/Volumes/Data", free_percent: 8, free_gb: 40, limit_percent: 10 }]);
    await checkin(55); // 11%: not enough above the limit to clear
    expect(await events("device.disk_ok")).toEqual([]);
    await checkin(100); // 20%
    expect(await events("device.disk_ok")).toHaveLength(1);
    // The organization's limit applies.
    await h.call("PATCH", "/v1/org/settings", { token: admin, body: { disk_low_percent: 25 } });
    await checkin(100);
    expect(await events("device.disk_low")).toHaveLength(2);
  });

  it("reports a device that stopped checking in, once, and when it's back", async () => {
    await h.call("PATCH", "/v1/org/settings", { token: admin, body: { device_offline_hours: 24 } });
    await db.query("UPDATE devices SET last_seen_at = now() - interval '23 hours' WHERE id = $1", [deviceId]);
    expect(await h.deps.db.tenant(orgId, (tx) => markOffline(tx, orgId, meta))).toBe(0);
    await db.query("UPDATE devices SET last_seen_at = now() - interval '25 hours' WHERE id = $1", [deviceId]);
    expect(await h.deps.db.tenant(orgId, (tx) => markOffline(tx, orgId, meta))).toBe(1);
    expect(await h.deps.db.tenant(orgId, (tx) => markOffline(tx, orgId, meta))).toBe(0); // one episode, one event
    expect(await events("device.went_offline")).toEqual([expect.objectContaining({ limit_hours: 24 })]);
    await checkin();
    expect(await events("device.back_online")).toHaveLength(1);
    expect((await db.query("SELECT offline_since FROM devices WHERE id = $1", [deviceId])).rows[0].offline_since).toBeNull();
  });

  it("raises alerts from the built-in rules, including compliance lost", async () => {
    // The firewall policy is enforced by default, with no grace period.
    await checkin(undefined, { posture: { ...posture, firewall: { status: "off" } } });
    expect(await events("device.compliance_changed")).toEqual(expect.arrayContaining([expect.objectContaining({ to: "non_compliant" })]));
    await evaluate(h.deps, orgId);
    expect(await alerts()).toEqual(expect.arrayContaining(["disk_low", "device_offline", "compliance_lost"]));
    const rules = (await h.call("GET", "/v1/alert-rules", { token: admin })).body.data.filter((r: any) => r.builtin).map((r: any) => r.name);
    expect(rules).toEqual(expect.arrayContaining(["Device offline", "Disk nearly full", "Device fell out of compliance"]));
  });
});

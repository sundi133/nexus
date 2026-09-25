import { compactVerify, importJWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** osquery: the scheduled inventory pack on check-in, software across devices, and live queries as signed commands. */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let helpdesk = "";
let analyst = "";
const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
async function enrolled(hostname: string) {
  const d = await new SoftDevice().init();
  const t = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: `t-${hostname}`, max_uses: 1 } });
  const payload = { token: t.body.token, device: { hostname, platform: "macos", os_name: "macOS", os_version: "15.1", os_build: "x", arch: "arm64", model: "Mac", serial: `S-${hostname}`, agent_version: "0.4.0" } };
  const r = await agentCall("/v1/agent/enroll", payload, await d.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  d.id = r.body.device_id;
  return d;
}
async function checkin(d: SoftDevice, extra: Record<string, unknown> = {}) {
  const payload = { device: { agent_version: "0.4.0" }, posture: healthy, ...extra };
  return agentCall("/v1/agent/checkin", payload, await d.proof("/v1/agent/checkin", JSON.stringify(payload)));
}
const report = (software: Record<string, string>[], extra: Record<string, unknown>[] = []) => ({
  available: true,
  version: "5.13.1",
  collected_at: "2026-09-25T10:00:00Z",
  results: [{ name: "software", rows: software }, { name: "listening_ports", rows: [{ process: "sshd", port: "22", protocol: "tcp", address: "0.0.0.0" }] }, ...extra],
});
const slack = { name: "Slack", version: "4.41.105", source: "app", publisher: "com.tinyspeck.slackmacgap" };

let mac: SoftDevice;
let mac2: SoftDevice;
let bare: SoftDevice;

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Osq Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  for (const [role, set] of [["helpdesk", (t: string) => (helpdesk = t)], ["security_analyst", (t: string) => (analyst = t)]] as const) {
    const email = uniqueEmail(role);
    await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: role, password: PASSWORD, roles: [role] } });
    set((await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token);
  }
  mac = await enrolled("sams-mac");
  mac2 = await enrolled("kims-mac");
  bare = await enrolled("no-osquery");
});
afterAll(() => h.close());

describe("inventory pack", () => {
  it("stores what the agent reports, and says when osquery is missing", async () => {
    const r = await checkin(mac, { osquery: report([slack, { name: "Zoom", version: "6.2.0", source: "app", publisher: "us.zoom.xos" }], [{ name: "usb_devices", rows: [], error: "Error: no such table: usb_devices" }]) });
    expect(r.status).toBe(200);
    expect(r.body.osquery_interval_seconds).toBe(21600);
    await checkin(mac2, { osquery: report([{ ...slack, version: "4.39.0" }, { name: "zoom", version: "6.2.0", source: "homebrew", publisher: "" }]) });
    await checkin(bare, { osquery: { available: false, collected_at: "2026-09-25T10:00:00Z", results: [] } });

    const inv = (await h.call("GET", `/v1/devices/${mac.id}/osquery`, { token: admin })).body;
    expect(inv).toMatchObject({ status: "installed", version: "5.13.1", collected_at: "2026-09-25T10:00:00.000Z" });
    expect(inv.tables.map((t: any) => t.name)).toEqual(["listening_ports", "software", "usb_devices"]);
    expect(inv.tables.find((t: any) => t.name === "usb_devices")).toMatchObject({ rows: [], error: "Error: no such table: usb_devices" });
    expect((await h.call("GET", `/v1/devices/${bare.id}/osquery`, { token: admin })).body).toMatchObject({ status: "not_installed", tables: [] });

    // A later report replaces the tables (usb_devices is gone from it).
    await checkin(mac, { osquery: report([slack]) });
    expect((await h.call("GET", `/v1/devices/${mac.id}/osquery`, { token: admin })).body.tables.map((t: any) => t.name)).toEqual(["listening_ports", "software"]);
  });

  it("ignores a malformed report without losing the check-in", async () => {
    const r = await checkin(mac2, { osquery: { available: true, results: "nope" } });
    expect(r.status).toBe(200);
    expect((await h.call("GET", `/v1/devices/${mac2.id}/osquery`, { token: admin })).body.tables).toHaveLength(2);
  });

  it("aggregates software across devices, by version", async () => {
    const s = (await h.call("GET", "/v1/software", { token: admin })).body;
    expect(s.devices_reporting).toBe(2);
    expect(s.data.find((x: any) => x.name === "Slack")).toEqual({ name: "Slack", source: "app", devices: 2, versions: [{ version: "4.41.105", devices: 1 }, { version: "4.39.0", devices: 1 }] });
    expect(s.data.find((x: any) => x.name === "zoom")).toMatchObject({ source: "homebrew", devices: 1 });
    expect((await h.call("GET", "/v1/software?q=sla", { token: admin })).body.data.map((x: any) => x.name)).toEqual(["Slack"]);
    const who = (await h.call("GET", "/v1/software/devices?name=Slack&version=4.39.0", { token: admin })).body.data;
    expect(who).toEqual([expect.objectContaining({ hostname: "kims-mac", version: "4.39.0" })]);
  });
});

describe("live queries", () => {
  let queryId = "";

  it("need devices:query, a reason, and a safe SELECT", async () => {
    const body = { sql: "SELECT name FROM apps", reason: "Hunting for an old Slack", target: { all: true } };
    expect((await h.call("POST", "/v1/live-queries", { token: helpdesk, body })).status).toBe(403);
    for (const [sql, why] of [
      ["SELECT * FROM curl WHERE url = 'https://attacker.example'", "curl"],
      ["DELETE FROM apps", "Only SELECT"],
      ["SELECT 1; SELECT 2", "One statement"],
      ["SELECT username, password_status FROM shadow", "password hashes"],
    ]) {
      const r = await h.call("POST", "/v1/live-queries", { token: analyst, body: { ...body, sql } });
      expect(r.status, sql).toBe(400);
      expect(r.body.title).toContain(why);
    }
    expect((await h.call("POST", "/v1/live-queries", { token: analyst, body: { ...body, target: { all: true, group_id: mac.id } } })).status).toBe(400);
  });

  it("goes to devices as a signed command with the SQL inside the signature", async () => {
    const r = await h.call("POST", "/v1/live-queries", { token: analyst, body: { sql: "SELECT name, version FROM apps WHERE name LIKE '%Slack%'", reason: "Hunting for an old Slack", target: { all: true } } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body).toMatchObject({ devices: 2, pending: 2, skipped_without_osquery: 1 });
    queryId = r.body.id;

    const ci = await checkin(mac);
    const cmd = ci.body.commands.find((x: any) => x);
    const key = await importJWK({ kty: "OKP", crv: "Ed25519", x: ci.body.command_key }, "EdDSA");
    const claims = JSON.parse(new TextDecoder().decode((await compactVerify(cmd.jws, key)).payload));
    expect(claims).toMatchObject({ act: "osquery", sub: mac.id, args: { sql: "SELECT name, version FROM apps WHERE name LIKE '%Slack%'" } });

    // The device answers on its next check-in.
    await checkin(mac, { command_results: [{ id: cmd.id, status: "done", output: "1 rows", data: { columns: ["version", "name"], rows: [{ name: "Slack", version: "4.41.105" }], truncated: false } }] });
    const k = (await checkin(mac2)).body.commands[0];
    await checkin(mac2, { command_results: [{ id: k.id, status: "done", output: "?", data: { rows: [{ name: { nested: true } }] } }] });

    const d = (await h.call("GET", `/v1/live-queries/${queryId}`, { token: analyst })).body;
    expect(d).toMatchObject({ devices: 2, done: 1, failed: 1, pending: 0, columns: ["version", "name"], rows: [{ _device: "sams-mac", name: "Slack", version: "4.41.105" }] });
    expect(d.results.find((x: any) => x.hostname === "kims-mac")).toMatchObject({ status: "failed", message: "The device returned rows Nexus couldn't read" });
    expect((await h.call("GET", "/v1/live-queries", { token: analyst })).body.data[0]).toMatchObject({ id: queryId, requested_by: expect.stringContaining("security_analyst") });
  });

  it("is audited once with its SQL, and stays out of the device's action history", async () => {
    const ev = (await h.call("GET", "/v1/audit/events?type=device.live_query", { token: admin })).body.data;
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ details: { sql: expect.stringContaining("FROM apps"), reason: "Hunting for an old Slack", devices: 2, skipped_without_osquery: 1 } });
    expect((await h.call("GET", "/v1/audit/events?type=device.action_finished", { token: admin })).body.data).toEqual([]);
    expect((await h.call("GET", `/v1/devices/${mac.id}/commands`, { token: admin })).body.data).toEqual([]);
  });

  it("can target specific devices, and not a device the org doesn't have", async () => {
    const r = await h.call("POST", "/v1/live-queries", { token: admin, body: { sql: "SELECT * FROM os_version", reason: "Check versions", target: { device_ids: [mac2.id] } } });
    expect(r.body).toMatchObject({ devices: 1 });
    const none = await h.call("POST", "/v1/live-queries", { token: admin, body: { sql: "SELECT 1", reason: "Check", target: { device_ids: ["00000000-0000-4000-8000-000000000000"] } } });
    expect(none.body.code).toBe("no_devices");
  });
});

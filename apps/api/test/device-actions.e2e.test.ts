import http from "node:http";
import type { AddressInfo } from "node:net";
import { compactVerify, importJWK } from "jose";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Device actions (DEV-09): signed agent commands (CMD-03) and MDM lock / restart / wipe. */

const TENANT = "11111111-2222-3333-4444-555555555555";
const CLIENT = "66666666-7777-8888-9999-000000000000";
const mdmCalls: { path: string; body: any }[] = [];
let failIntune = false;
let server: http.Server;
let base = "";

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let helpdesk = "";
let orgId = "";
let enrollKey = "";
const mac = new SoftDevice();
const other = new SoftDevice();

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
async function enroll(d: SoftDevice, serial: string, hostname: string) {
  await d.init();
  const t = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: `t-${serial}`, max_uses: 1 } });
  const payload = { token: t.body.token, device: { hostname, platform: "macos", os_name: "macOS", os_version: "15.1", os_build: "x", arch: "arm64", model: "Mac", serial, agent_version: "0.3.0" } };
  const r = await agentCall("/v1/agent/enroll", payload, await d.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  d.id = r.body.device_id;
  return r.body;
}
async function checkin(d: SoftDevice, extra: Record<string, unknown> = {}) {
  const payload = { device: { agent_version: "0.3.0" }, posture: healthy, ...extra };
  return (await agentCall("/v1/agent/checkin", payload, await d.proof("/v1/agent/checkin", JSON.stringify(payload)))).body;
}
const act = (id: string, body: Record<string, unknown>, token = admin) => h.call("POST", `/v1/devices/${id}/actions`, { token, body });
const commands = async (id: string) => (await h.call("GET", `/v1/devices/${id}/commands`, { token: admin })).body.data as Record<string, any>[];

beforeAll(async () => {
  server = http.createServer((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c)).on("end", () => {
      const json = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
      const url = new URL(req.url!, base);
      if (url.pathname === `/entra/${TENANT}/oauth2/v2.0/token`) return json(200, { access_token: "graph-token" });
      if (url.pathname === "/graph/v1.0/deviceManagement/managedDevices" && req.method === "GET") {
        return json(200, { value: [{ id: "intune-1", deviceName: "ceo-mbp", serialNumber: "C02CEO", operatingSystem: "macOS", complianceState: "compliant", managementState: "managed" }] });
      }
      if (url.pathname.startsWith("/graph/v1.0/deviceManagement/managedDevices/")) {
        mdmCalls.push({ path: url.pathname, body: data ? JSON.parse(data) : null });
        if (failIntune) return json(403, { error: { message: "Missing DeviceManagementManagedDevices.PrivilegedOperations.All" } });
        return res.writeHead(204).end();
      }
      if (url.pathname === "/jamf/api/oauth/token") return json(200, { access_token: "jamf-token" });
      if (url.pathname === "/jamf/api/v1/computers-inventory") {
        return json(200, { totalCount: 1, results: url.searchParams.get("page") === "0" ? [{ id: "7", general: { name: "design-imac", managementId: "mgmt-uuid-7", remoteManagement: { managed: true } }, hardware: { serialNumber: "C02DESIGN" } }] : [] });
      }
      if (url.pathname === "/jamf/api/v2/mdm/commands") {
        mdmCalls.push({ path: url.pathname, body: JSON.parse(data) });
        return json(201, [{ id: "cmd-1", href: "/api/v2/mdm/commands/cmd-1" }]);
      }
      res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  h = await bootApp({ entraLoginBase: `${base}/entra`, graphBase: `${base}/graph` });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Actions Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Helen", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;
  enrollKey = (await enroll(mac, "C02SAM", "sams-mbp")).command_key;
  await enroll(other, "C02OTHER", "other-mbp");
});
afterAll(async () => {
  server.close();
  await owner.end();
  await h.close();
});

describe("signed agent commands", () => {
  it("gives the agent the organization's command key at enrollment and on check-in", async () => {
    expect(enrollKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect((await checkin(mac)).command_key).toBe(enrollKey);
    expect((await checkin(mac)).commands).toEqual([]);
  });

  it("delivers a refresh signed for this device only, and records the result", async () => {
    const r = await act(mac.id, { action: "refresh" });
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    expect(r.body.command).toMatchObject({ action: "refresh", channel: "agent", status: "queued" });
    expect((await checkin(other)).commands).toEqual([]); // not for other devices
    const res = await checkin(mac);
    expect(res.commands).toHaveLength(1);
    const cmd = res.commands[0];
    const key = await importJWK({ kty: "OKP", crv: "Ed25519", x: enrollKey }, "EdDSA");
    const { payload, protectedHeader } = await compactVerify(cmd.jws, key);
    expect(protectedHeader).toEqual({ alg: "EdDSA", typ: "nexus-command+jwt" });
    const claims = JSON.parse(new TextDecoder().decode(payload));
    expect(claims).toMatchObject({ jti: cmd.id, sub: mac.id, act: "refresh" });
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
    expect((await commands(mac.id))[0]!.status).toBe("sent");

    // Another device can't settle it.
    await checkin(other, { command_results: [{ id: cmd.id, status: "failed", output: "spoof" }] });
    expect((await commands(mac.id))[0]!.status).toBe("sent");
    await checkin(mac, { command_results: [{ id: cmd.id, status: "done", output: "Reported" }] });
    expect((await commands(mac.id))[0]).toMatchObject({ status: "done", output: "Reported", finished_at: expect.any(String) });
    const ev = (await h.call("GET", "/v1/audit/events?type=device.action_finished", { token: admin })).body.data[0];
    expect(ev).toMatchObject({ actor: { display: "sams-mbp" }, details: { action: "refresh", status: "done" } });
  });

  it("locks through the agent when there's no MDM, with a reason, and tells admins", async () => {
    expect((await act(mac.id, { action: "lock" })).body.code).toBe("reason_required");
    const r = await act(mac.id, { action: "lock", reason: "Laptop left unlocked in a café" }, helpdesk);
    expect(r.body.command).toMatchObject({ action: "lock", channel: "agent", status: "queued", reason: "Laptop left unlocked in a café" });
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin })).body.data;
    expect(inbox[0].title).toMatch(/locked sams-mbp$/);
    // Canceled before the device picks it up: never delivered.
    const c = await h.call("POST", `/v1/devices/${mac.id}/commands/${r.body.command.id}/cancel`, { token: admin, body: {} });
    expect(c.body.data[0].status).toBe("canceled");
    expect((await checkin(mac)).commands).toEqual([]);
  });

  it("doesn't deliver expired commands", async () => {
    const r = await act(mac.id, { action: "restart", reason: "Apply the security update" });
    await owner.query("UPDATE device_commands SET expires_at = now() - interval '1 minute' WHERE id = $1", [r.body.command.id]);
    expect((await checkin(mac)).commands).toEqual([]);
    expect((await commands(mac.id)).find((x) => x.id === r.body.command.id)!.status).toBe("expired");
  });

  it("can't wipe without an MDM, a matching confirmation, or the permission", async () => {
    expect((await act(mac.id, { action: "wipe", reason: "Stolen", confirm: "sams-mbp" })).body.code).toBe("no_mdm");
    expect((await act(mac.id, { action: "wipe", reason: "Stolen", confirm: "wrong" })).body.code).toBe("confirm_mismatch");
    expect((await act(mac.id, { action: "wipe", reason: "Stolen", confirm: "sams-mbp" }, helpdesk)).status).toBe(403);
  });
});

describe("through the MDM", () => {
  let ceo: SoftDevice;
  let imac: SoftDevice;

  beforeAll(async () => {
    ceo = new SoftDevice();
    imac = new SoftDevice();
    await enroll(ceo, "C02CEO", "ceo-mbp");
    await enroll(imac, "C02DESIGN", "design-imac");
    await h.call("POST", "/v1/mdm/connections", { token: admin, body: { name: "Intune", credentials: { provider: "intune", tenant_id: TENANT, client_id: CLIENT, client_secret: "s" } } });
    await h.call("POST", "/v1/mdm/connections", { token: admin, body: { name: "Jamf", credentials: { provider: "jamf", base_url: `${base}/jamf`, client_id: "c", client_secret: "s" } } });
    await h.jobs.runOnce({ orgId });
  });

  it("locks and wipes with Intune", async () => {
    const lock = await act(ceo.id, { action: "lock", reason: "Reported lost" });
    expect(lock.status, JSON.stringify(lock.body)).toBe(202);
    expect(lock.body).toMatchObject({ command: { channel: "mdm", status: "done", output: "Sent to Microsoft Intune (Intune)" }, unlock_pin: null });
    expect(mdmCalls.at(-1)!.path).toBe("/graph/v1.0/deviceManagement/managedDevices/intune-1/remoteLock");
    const wipe = await act(ceo.id, { action: "wipe", reason: "Stolen, police report 1234", confirm: "ceo-mbp" });
    expect(wipe.body.command).toMatchObject({ action: "wipe", channel: "mdm", status: "done" });
    expect(mdmCalls.at(-1)).toEqual({ path: "/graph/v1.0/deviceManagement/managedDevices/intune-1/wipe", body: { keepEnrollmentData: false, keepUserData: false } });
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin })).body.data;
    expect(inbox.find((n: any) => n.title.endsWith("wiped ceo-mbp"))).toMatchObject({ severity: "critical", body: "Stolen, police report 1234" });
  });

  it("reports what the MDM refused", async () => {
    failIntune = true;
    const r = await act(ceo.id, { action: "lock", reason: "Again" });
    failIntune = false;
    expect(r).toMatchObject({ status: 502, body: { code: "mdm_failed", title: expect.stringContaining("PrivilegedOperations") } });
    expect((await commands(ceo.id))[0]).toMatchObject({ action: "lock", status: "failed" });
    const ev = (await h.call("GET", "/v1/audit/events?type=device.action_requested", { token: admin })).body.data[0];
    expect(ev).toMatchObject({ outcome: "failure", details: { action: "lock", channel: "mdm" } });
  });

  it("locks a Mac with Jamf, and hands back its unlock PIN once", async () => {
    const r = await act(imac.id, { action: "lock", reason: "Left in a meeting room" });
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    expect(r.body.unlock_pin).toMatch(/^\d{6}$/);
    expect(mdmCalls.at(-1)).toEqual({ path: "/jamf/api/v2/mdm/commands", body: { clientData: [{ managementId: "mgmt-uuid-7" }], commandData: { commandType: "DEVICE_LOCK", pin: r.body.unlock_pin } } });
    expect(JSON.stringify(await commands(imac.id))).not.toContain(r.body.unlock_pin);
  });
});

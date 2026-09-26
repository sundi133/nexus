import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** MDM signals (Intune, Jamf Pro): matched by serial, used by the "managed and compliant" policy. */

const TENANT = "11111111-2222-3333-4444-555555555555";
const CLIENT = "66666666-7777-8888-9999-000000000000";
const intune = {
  secret: "intune-secret",
  devices: [
    { id: "i1", deviceName: "SAMS-MBP", serialNumber: "C02MDM1", operatingSystem: "macOS", osVersion: "15.1", complianceState: "noncompliant", isEncrypted: true, userPrincipalName: "sam@acme.com", lastSyncDateTime: "2026-09-25T10:00:00Z", managementState: "managed" },
    { id: "i2", deviceName: "KIOSK-7", serialNumber: "PF3KIOSK", operatingSystem: "Windows", osVersion: "10.0.22631", complianceState: "compliant", isEncrypted: true, userPrincipalName: "", lastSyncDateTime: "2026-09-25T09:00:00Z", managementState: "managed" },
    { id: "i3", deviceName: "LAB-PC", serialNumber: "PF3LAB", operatingSystem: "Windows", osVersion: "10.0.19045", complianceState: "inGracePeriod", isEncrypted: false, userPrincipalName: "lab@acme.com", lastSyncDateTime: "0001-01-01T00:00:00Z", managementState: "managed" },
  ] as Record<string, unknown>[],
};
const jamf = {
  secret: "jamf-secret",
  computers: [
    { id: "1", general: { name: "Design-iMac", remoteManagement: { managed: true }, lastContactTime: "2026-09-25T08:00:00Z" }, hardware: { serialNumber: "C02JAMF1" }, operatingSystem: { version: "14.6" }, diskEncryption: { fileVault2Status: "ALL_ENCRYPTED" }, userAndLocation: { email: "des@acme.com" } },
    { id: "2", general: { name: "Old-Mini", remoteManagement: { managed: false } }, hardware: { serialNumber: "C02JAMF2" }, operatingSystem: { version: "12.7" }, diskEncryption: { fileVault2Status: "NOT_ENCRYPTED" }, userAndLocation: {} },
  ] as Record<string, unknown>[],
};
const hits: string[] = [];
let server: http.Server;
let base = "";

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let orgId = "";
let intuneId = "";

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
async function enrolledDevice(serial: string) {
  const d = await new SoftDevice().init();
  const t = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: `t-${serial}`, max_uses: 1 } });
  const payload = { token: t.body.token, device: { hostname: `host-${serial}`, platform: "macos", os_name: "macOS", os_version: "15.1", os_build: "x", arch: "arm64", model: "Mac", serial, agent_version: "0.1.0" } };
  const r = await agentCall("/v1/agent/enroll", payload, await d.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  d.id = r.body.device_id;
  return d;
}
async function checkin(d: SoftDevice) {
  const payload = { device: { agent_version: "0.1.0" }, posture: healthy };
  return agentCall("/v1/agent/checkin", payload, await d.proof("/v1/agent/checkin", JSON.stringify(payload)));
}
const device = async (id: string) => (await h.call("GET", `/v1/devices/${id}`, { token: admin })).body;
const conns = async () => (await h.call("GET", "/v1/mdm/connections", { token: admin })).body.data as Record<string, any>[];
const sync = async () => {
  await h.jobs.runOnce({ orgId });
};

beforeAll(async () => {
  server = http.createServer((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c)).on("end", () => {
      const json = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
      const url = new URL(req.url!, base);
      hits.push(url.pathname);
      if (url.pathname === `/entra/${TENANT}/oauth2/v2.0/token`) {
        const f = new URLSearchParams(data);
        if (f.get("client_secret") !== intune.secret) return json(401, { error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided." });
        return json(200, { access_token: "graph-token" });
      }
      if (url.pathname === "/graph/v1.0/deviceManagement/managedDevices") {
        if (req.headers.authorization !== "Bearer graph-token") return json(401, {});
        // Two pages, to follow @odata.nextLink.
        if (!url.searchParams.get("page")) return json(200, { value: intune.devices.slice(0, 2), "@odata.nextLink": `${base}/graph/v1.0/deviceManagement/managedDevices?page=2` });
        return json(200, { value: intune.devices.slice(2) });
      }
      if (url.pathname === "/jamf/api/oauth/token") {
        return new URLSearchParams(data).get("client_secret") === jamf.secret ? json(200, { access_token: "jamf-token", expires_in: 1200 }) : json(401, { error: "invalid_client" });
      }
      if (url.pathname === "/jamf/api/v1/computers-inventory") {
        if (req.headers.authorization !== "Bearer jamf-token") return json(401, {});
        expect(url.searchParams.getAll("section")).toContain("HARDWARE");
        return json(200, { totalCount: jamf.computers.length, results: url.searchParams.get("page") === "0" ? jamf.computers : [] });
      }
      res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  h = await bootApp({ entraLoginBase: `${base}/entra`, graphBase: `${base}/graph` });
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "MDM Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
});
afterAll(async () => {
  server.close();
  await h.close();
});

describe("connecting Intune", () => {
  it("tries the credentials first", async () => {
    const bad = await h.call("POST", "/v1/mdm/connections", { token: admin, body: { name: "Intune", credentials: { provider: "intune", tenant_id: TENANT, client_id: CLIENT, client_secret: "wrong" } } });
    expect(bad.body).toMatchObject({ code: "mdm_unreachable", title: expect.stringContaining("Invalid client secret") });
    const r = await h.call("POST", "/v1/mdm/connections", { token: admin, body: { name: "Intune", credentials: { provider: "intune", tenant_id: TENANT, client_id: CLIENT, client_secret: intune.secret } } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.found).toBe(3); // both pages
    intuneId = r.body.data[0].id;
    expect(JSON.stringify(r.body)).not.toContain(intune.secret);
  });

  it("syncs, matches by serial, and shows the coverage gap", async () => {
    const sam = await enrolledDevice("c02mdm1"); // serials match case-insensitively
    await checkin(sam);
    await sync();
    expect((await conns())[0]).toMatchObject({ provider_name: "Microsoft Intune", last_status: "ok", devices: 3, matched: 1, without_agent: 2, noncompliant: 1 });
    const gap = await h.call("GET", `/v1/mdm/connections/${intuneId}/devices?without_agent=true`, { token: admin });
    expect(gap.body.data.map((d: any) => d.name).sort()).toEqual(["KIOSK-7", "LAB-PC"]);
    expect(gap.body.data.find((d: any) => d.name === "LAB-PC")).toMatchObject({ compliant: true, encrypted: false, last_contact_at: null, platform: "windows" });
    expect((await device(sam.id)).mdm).toEqual([expect.objectContaining({ source: "Microsoft Intune", managed: true, compliant: false })]);
  });
});

describe("the policy", () => {
  it("is off until an admin turns it on, then Intune's verdict counts", async () => {
    const sam = await enrolledDevice("C02MDM1B");
    expect((await checkin(sam)).body.compliance).toBe("compliant");
    const pol = (await h.call("GET", "/v1/device-policies", { token: admin })).body.data.find((p: any) => p.key === "mdm_compliant");
    expect(pol).toMatchObject({ enabled: false, title: "Managed and compliant in your MDM" });
    await h.call("PUT", "/v1/device-policies/mdm_compliant", { token: admin, body: { enabled: true, params: {} } });
    // This one isn't in Intune at all.
    expect((await device(sam.id)).checks.find((c: any) => c.key === "mdm_compliant")).toMatchObject({ status: "fail", detail: "Not found in your MDM (serial C02MDM1B)" });

    const matched = (await h.call("GET", "/v1/devices?limit=50", { token: admin })).body.data.find((d: any) => d.serial === "c02mdm1");
    const d = await device(matched.id);
    expect(d.compliance).toBe("non_compliant");
    expect(d.checks.find((c: any) => c.key === "mdm_compliant")).toMatchObject({ status: "fail", detail: "Microsoft Intune reports it non-compliant" });

    // Fixed in Intune: the next sync re-evaluates.
    intune.devices[0]!.complianceState = "compliant";
    await h.call("POST", `/v1/mdm/connections/${intuneId}/sync`, { token: admin, body: {} });
    await sync();
    expect((await device(matched.id)).compliance).toBe("compliant");
  });

  it("matches a newly enrolled device at once, without waiting for the next sync", async () => {
    intune.devices.push({ id: "i4", deviceName: "NEW-MBP", serialNumber: "C02NEW", operatingSystem: "macOS", osVersion: "15.1", complianceState: "compliant", managementState: "managed" });
    await h.call("POST", `/v1/mdm/connections/${intuneId}/sync`, { token: admin, body: {} });
    await sync();
    const fresh = await enrolledDevice("C02NEW");
    expect((await checkin(fresh)).body.compliance).toBe("compliant");
    expect((await device(fresh.id)).checks.find((c: any) => c.key === "mdm_compliant")).toMatchObject({ status: "pass", detail: "Compliant in Microsoft Intune" });
  });
});

describe("serials that don't identify one machine", () => {
  const mdmCheck = async (id: string) => (await device(id)).checks.find((c: any) => c.key === "mdm_compliant");
  it("never lends another machine's verdict, or makes it a wipe target", async () => {
    const managed = { operatingSystem: "Windows", osVersion: "10.0.22631", complianceState: "compliant", isEncrypted: true, managementState: "managed" };
    intune.devices.push(
      { id: "i5", deviceName: "WHITEBOX-1", serialNumber: "To Be Filled By O.E.M.", ...managed },
      { id: "i6", deviceName: "VDI-A", serialNumber: "VMCLONE01", ...managed },
      { id: "i7", deviceName: "VDI-B", serialNumber: "vmclone01", ...managed },
      { id: "i8", deviceName: "SHARED", serialNumber: "PF3DUPE", ...managed },
    );
    await h.call("POST", `/v1/mdm/connections/${intuneId}/sync`, { token: admin, body: {} });
    await sync();

    // A placeholder serial: never matched, and the check says why.
    const oem = await enrolledDevice("To Be Filled By O.E.M.");
    await checkin(oem);
    expect(await mdmCheck(oem.id)).toMatchObject({ status: "fail", detail: expect.stringContaining("manufacturer placeholder") });
    expect((await device(oem.id)).mdm).toEqual([]);
    const wipe = await h.call("POST", `/v1/devices/${oem.id}/actions`, { token: admin, body: { action: "wipe", reason: "Stolen", confirm: "host-To Be Filled By O.E.M." } });
    expect(wipe.body.code).toBe("no_mdm");

    // Two MDM records with the same serial (cloned VMs): neither is picked.
    const clone = await enrolledDevice("VMCLONE01");
    await checkin(clone);
    expect(await mdmCheck(clone.id)).toMatchObject({ status: "fail", detail: "Not found in your MDM (serial VMCLONE01)" });

    // Two Nexus devices with the same serial: neither gets the MDM's verdict, before or after a sync.
    const a = await enrolledDevice("PF3DUPE");
    const b = await enrolledDevice("PF3DUPE");
    await checkin(a);
    await checkin(b);
    await h.call("POST", `/v1/mdm/connections/${intuneId}/sync`, { token: admin, body: {} });
    await sync();
    for (const d of [a, b]) expect((await device(d.id)).mdm).toEqual([]);
    const rows = (await h.call("GET", `/v1/mdm/connections/${intuneId}/devices?without_agent=true`, { token: admin })).body.data.map((d: any) => d.name);
    expect(rows).toEqual(expect.arrayContaining(["WHITEBOX-1", "VDI-A", "VDI-B", "SHARED"]));
    intune.devices.splice(4);
  });
});

describe("Jamf Pro", () => {
  it("reads managed Macs and their FileVault state", async () => {
    const r = await h.call("POST", "/v1/mdm/connections", { token: admin, body: { name: "Jamf", credentials: { provider: "jamf", base_url: `${base}/jamf`, client_id: "nexus", client_secret: jamf.secret } } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const id = r.body.data.find((c: any) => c.provider === "jamf").id;
    await sync();
    const devs = (await h.call("GET", `/v1/mdm/connections/${id}/devices`, { token: admin })).body.data;
    expect(devs.find((d: any) => d.name === "Design-iMac")).toMatchObject({ managed: true, compliant: null, encrypted: true, user_email: "des@acme.com" });
    expect(devs.find((d: any) => d.name === "Old-Mini")).toMatchObject({ managed: false, compliant: false, compliance_detail: "FileVault is off" });
    const mini = await enrolledDevice("C02JAMF2");
    await checkin(mini);
    expect((await device(mini.id)).checks.find((c: any) => c.key === "mdm_compliant")).toMatchObject({ status: "fail", detail: "Not managed by Jamf Pro" });
  });
});

describe("failures", () => {
  it("records a broken connection and tells admins once", async () => {
    intune.secret = "rotated-at-microsoft";
    for (let i = 0; i < 2; i++) {
      await h.call("POST", `/v1/mdm/connections/${intuneId}/sync`, { token: admin, body: {} });
      await sync();
    }
    expect((await conns()).find((c) => c.id === intuneId)).toMatchObject({ last_status: "error", last_error: expect.stringContaining("Invalid client secret") });
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=10&filter=all", { token: admin })).body.data;
    expect(inbox.filter((n: any) => n.title === "Can't read Intune")).toHaveLength(1);
  });

  it("stops counting when disconnected", async () => {
    await h.call("DELETE", `/v1/mdm/connections/${intuneId}`, { token: admin });
    const rest = await conns();
    for (const c of rest) await h.call("DELETE", `/v1/mdm/connections/${c.id}`, { token: admin });
    const any = (await h.call("GET", "/v1/devices?limit=50", { token: admin })).body.data[0];
    expect((await device(any.id)).checks.find((c: any) => c.key === "mdm_compliant")).toMatchObject({ status: "not_applicable", detail: "No MDM connected" });
  });
});

import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** App deployment: the catalog, assignments, the apps in each device's signed policy, and their state. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let helpdesk = "";
let orgId = "";
let groupId = "";
const devices: Record<string, { d: SoftDevice; id: string }> = {};

const posture = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
async function checkin(name: string, extra: Record<string, unknown> = {}) {
  const body = JSON.stringify({ device: { agent_version: "0.2.0" }, posture, ...extra });
  const res = await h.app.request("/v1/agent/checkin", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await devices[name]!.d.proof("/v1/agent/checkin", body)}` }, body });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, any>;
}
const policyOf = (jws: string) => JSON.parse(Buffer.from(jws.split(".")[1]!, "base64url").toString());
const appsOf = async (name: string) => policyOf((await checkin(name)).enforcement).software as any[];
const SHA = "a".repeat(64);

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Deploy Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;
  const eng = (await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("eng"), given_name: "Eve" } })).body.id;
  groupId = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "Engineering" } })).body.id;
  await h.call("POST", `/v1/groups/${groupId}/members`, { token: admin, body: { user_ids: [eng] } });
  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "all" } })).body.token;
  for (const [name, platform] of [["win", "windows"], ["mac", "macos"], ["dev-box", "linux"], ["kiosk", "linux"]] as const) {
    const d = await new SoftDevice().init();
    const body = JSON.stringify({ token: t, device: { hostname: name, platform, os_version: "1", agent_version: "0.2.0" } });
    const res = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof("/v1/agent/enroll", body, { enroll: true })}` }, body });
    d.id = ((await res.json()) as any).device_id;
    devices[name] = { d, id: d.id };
  }
  await db.query("UPDATE devices SET primary_user_id = $1 WHERE id = $2", [eng, devices["dev-box"]!.id]);
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("app deployment", () => {
  const ids: Record<string, string> = {};

  it("keeps a catalog only owners and admins can change, of installers the agent can verify", async () => {
    const zoom = { name: "Zoom", kind: "winget", ref: "Zoom.Zoom" };
    expect((await h.call("POST", "/v1/software-packages", { token: helpdesk, body: zoom })).status).toBe(403);
    const bad = async (body: object) => (await h.call("POST", "/v1/software-packages", { token: admin, body })).body.code;
    expect(await bad({ name: "x", kind: "apt", ref: "--allow-unauthenticated" })).toBe("invalid_ref");
    expect(await bad({ name: "x", kind: "msi", ref: "{11111111-2222-3333-4444-555555555555}", url: "http://example.com/a.msi", sha256: SHA })).toBe("invalid_url");
    expect(await bad({ name: "x", kind: "pkg", ref: "com.example.app", url: "https://example.com/a.pkg" })).toBe("invalid_sha256");
    expect(await bad({ name: "x", kind: "apt", ref: "htop", url: "https://example.com/htop.deb" })).toBe("invalid_url");

    for (const [k, body] of Object.entries({
      zoom,
      agentMsi: { name: "Acme VPN", kind: "msi", ref: "{11111111-2222-3333-4444-555555555555}", url: "https://downloads.example.com/vpn.msi", sha256: SHA.toUpperCase(), args: ["ALLUSERS=1"] },
      slack: { name: "Slack", kind: "pkg", ref: "com.tinyspeck.slackmacgap", url: "https://downloads.example.com/slack.pkg", sha256: SHA },
      htop: { name: "htop", kind: "apt", ref: "htop" },
    })) {
      const r = await h.call("POST", "/v1/software-packages", { token: admin, body });
      expect(r.status).toBe(201);
      ids[k] = r.body.id;
    }
    const list = (await h.call("GET", "/v1/software-packages", { token: helpdesk })).body.data;
    expect(list.map((p: any) => [p.name, p.platform])).toEqual([["Acme VPN", "windows"], ["htop", "linux"], ["Slack", "macos"], ["Zoom", "windows"]]);
    expect(list[0].sha256).toBe(SHA); // stored lower-case, as the agent compares it
  });

  it("puts assigned apps in each device's signed policy: everyone, a group, install beats remove", async () => {
    expect((await appsOf("win"))).toEqual([]);
    await h.call("POST", `/v1/software-packages/${ids.zoom}/assignments`, { token: admin, body: { action: "install" } });
    await h.call("POST", `/v1/software-packages/${ids.htop}/assignments`, { token: admin, body: { action: "remove" } });
    const r = await h.call("POST", `/v1/software-packages/${ids.htop}/assignments`, { token: admin, body: { action: "install", group_id: groupId } });
    expect(r.body.assignments.map((a: any) => [a.action, a.group_name])).toEqual([["remove", null], ["install", "Engineering"]]);
    expect((await h.call("POST", `/v1/software-packages/${ids.zoom}/assignments`, { token: admin, body: { action: "install" } })).status).toBe(409);
    expect((await h.call("POST", `/v1/software-packages/${ids.slack}/assignments`, { token: admin, body: { action: "remove" } })).body.code).toBe("cannot_remove");
    await h.call("POST", `/v1/software-packages/${ids.agentMsi}/assignments`, { token: admin, body: { action: "install", group_id: groupId } }); // no Windows device in it

    expect(await appsOf("win")).toEqual([{ id: ids.zoom, name: "Zoom", action: "install", kind: "winget", ref: "Zoom.Zoom" }]);
    expect(await appsOf("dev-box")).toEqual([{ id: ids.htop, name: "htop", action: "install", kind: "apt", ref: "htop" }]);
    expect(await appsOf("kiosk")).toEqual([{ id: ids.htop, name: "htop", action: "remove", kind: "apt", ref: "htop" }]);
    expect(await appsOf("mac")).toEqual([]);

    // An MSI carries its URL, hash and arguments.
    await db.query("UPDATE devices SET primary_user_id = (SELECT primary_user_id FROM devices WHERE id = $1) WHERE id = $2", [devices["dev-box"]!.id, devices.win!.id]);
    expect((await appsOf("win")).find((a) => a.kind === "msi")).toEqual({ id: ids.agentMsi, name: "Acme VPN", action: "install", kind: "msi", ref: "{11111111-2222-3333-4444-555555555555}", url: "https://downloads.example.com/vpn.msi", sha256: SHA, args: ["ALLUSERS=1"] });
  });

  it("records what each device reports, counts it, and audits installs and failures", async () => {
    const pol = policyOf((await checkin("win")).enforcement);
    await checkin("win", {
      enforcement: {
        version: pol.ver,
        software: [
          { id: ids.agentMsi, status: "installed", detail: "installed by Nexus" },
          { id: ids.zoom, status: "failed", detail: "winget (App Installer) isn't on this device" },
          { id: "not-a-package", status: "installed" },
        ],
      },
    });
    await checkin("kiosk", { enforcement: { software: [{ id: ids.htop, status: "absent", detail: "" }] } });
    const list = (await h.call("GET", "/v1/software-packages", { token: admin })).body.data;
    const by = (n: string) => list.find((p: any) => p.name === n).counts;
    expect(by("Zoom")).toEqual({ targeted: 1, installed: 0, absent: 0, failed: 1, unsupported: 0, pending: 0 });
    expect(by("Acme VPN")).toMatchObject({ targeted: 1, installed: 1 });
    expect(by("htop")).toMatchObject({ targeted: 2, absent: 1, pending: 1 });
    const per = (await h.call("GET", `/v1/software-packages/${ids.htop}/devices`, { token: helpdesk })).body.data;
    expect(per.map((d: any) => [d.hostname, d.action, d.status])).toEqual([["dev-box", "install", "pending"], ["kiosk", "remove", "absent"]]);

    const types = (await db.query("SELECT type, details->>'package' AS pkg FROM audit_events WHERE org_id = $1 AND type LIKE 'device.software_%ed' AND type NOT LIKE '%saved' AND type NOT LIKE '%assigned' ORDER BY id", [orgId])).rows;
    expect(types).toEqual([{ type: "device.software_installed", pkg: "Acme VPN" }, { type: "device.software_failed", pkg: "Zoom" }]);
    // The same failure reported again isn't audited again.
    await checkin("win", { enforcement: { software: [{ id: ids.agentMsi, status: "installed", detail: "installed by Nexus" }, { id: ids.zoom, status: "failed", detail: "winget (App Installer) isn't on this device" }] } });
    expect((await db.query("SELECT count(*)::int AS n FROM audit_events WHERE org_id = $1 AND type = 'device.software_failed'", [orgId])).rows[0].n).toBe(1);

    // The enforcement view counts the apps in the version it expects.
    const enf = (await h.call("GET", `/v1/devices/${devices.win!.id}/enforcement`, { token: admin })).body;
    expect(enf.expected_version).toBe(pol.ver);
  });

  it("an unassigned app leaves the policy, and its state goes when the device stops reporting it", async () => {
    const zoom = (await h.call("GET", "/v1/software-packages", { token: admin })).body.data.find((p: any) => p.name === "Zoom");
    expect((await h.call("DELETE", `/v1/software-packages/${ids.zoom}/assignments/${zoom.assignments[0].id}`, { token: helpdesk })).status).toBe(403);
    expect((await h.call("DELETE", `/v1/software-packages/${ids.zoom}/assignments/${zoom.assignments[0].id}`, { token: admin })).status).toBe(204);
    expect((await appsOf("win")).map((a) => a.name)).toEqual(["Acme VPN"]);
    await checkin("win", { enforcement: { software: [{ id: ids.agentMsi, status: "installed" }] } });
    expect((await db.query("SELECT count(*)::int AS n FROM device_software WHERE device_id = $1", [devices.win!.id])).rows[0].n).toBe(1);
    // An older agent that doesn't report apps leaves the state alone.
    await checkin("win", { enforcement: { version: "x" } });
    expect((await db.query("SELECT count(*)::int AS n FROM device_software WHERE device_id = $1", [devices.win!.id])).rows[0].n).toBe(1);
  });
});

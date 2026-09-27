import { compactVerify, importJWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { evaluate } from "../src/alerts/engine.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Device enforcement: block rules, the signed per-device policy, and what agents report. */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let analyst = "";
let orgId = "";
let groupId = "";
let samId = "";
const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
async function enrolled(hostname: string, platform = "macos", assign?: string) {
  const d = await new SoftDevice().init();
  const t = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: `t-${hostname}`, max_uses: 1 } });
  const payload = { token: t.body.token, device: { hostname, platform, os_name: platform, os_version: "15.1", os_build: "x", arch: "arm64", model: "M", serial: `S-${hostname}`, agent_version: "0.5.0" } };
  const r = await agentCall("/v1/agent/enroll", payload, await d.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  d.id = r.body.device_id;
  if (assign) await h.call("PATCH", `/v1/devices/${d.id}`, { token: admin, body: { primary_user_id: assign } });
  return d;
}
async function checkin(d: SoftDevice, extra: Record<string, unknown> = {}) {
  const payload = { device: { agent_version: "0.5.0" }, posture: healthy, ...extra };
  return agentCall("/v1/agent/checkin", payload, await d.proof("/v1/agent/checkin", JSON.stringify(payload)));
}
async function policyOf(d: SoftDevice) {
  const r = (await checkin(d)).body;
  const key = await importJWK({ kty: "OKP", crv: "Ed25519", x: r.command_key }, "EdDSA");
  const v = await compactVerify(r.enforcement, key);
  expect(v.protectedHeader.typ).toBe("nexus-policy+jwt");
  return JSON.parse(new TextDecoder().decode(v.payload)) as { sub: string; ts: number; ver: string; rules: { name: string; kind: string; value: string; mode: string }[] };
}
const rule = (body: Record<string, unknown>, token = admin) => h.call("POST", "/v1/enforcement/rules", { token, body: { reason: "Pilot test", ...body } });

let mac: SoftDevice;
let win: SoftDevice;
let lab: SoftDevice;

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Enforce Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  const email = uniqueEmail("analyst");
  await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Ana", password: PASSWORD, roles: ["security_analyst"] } });
  analyst = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
  samId = (await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("sam"), given_name: "Sam" } })).body.id;
  groupId = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "Contractors" } })).body.id;
  await h.call("POST", `/v1/groups/${groupId}/members`, { token: admin, body: { user_ids: [samId] } });
  await evaluate(h.deps, orgId); // alerting follows the audit log from here
  mac = await enrolled("sams-mac", "macos", samId);
  win = await enrolled("front-desk", "windows");
  lab = await enrolled("lab-box", "linux");
});
afterAll(() => h.close());

describe("rules", () => {
  it("need devices:enforce, and refuse what would break a device or cut it off from Nexus", async () => {
    expect((await rule({ name: "x", kind: "app", match: "name", value: "Cursor" }, analyst)).status).toBe(403);
    const apiHost = new URL(h.deps.cfg.apiPublicUrl).hostname;
    for (const [body, why] of [
      [{ kind: "app", match: "name", value: "launchd" }, "operating system"],
      [{ kind: "app", match: "name", value: "svchost.exe" }, "operating system"],
      [{ kind: "app", match: "name", value: "nexus-agent" }, "Nexus"],
      [{ kind: "app", match: "path", value: "/" }, "every program"],
      [{ kind: "app", match: "path", value: "/System/Library/" }, "operating system or Nexus"],
      [{ kind: "app", match: "path", value: "relative/path" }, "full path"],
      [{ kind: "app", match: "sha256", value: "abc" }, "64 hexadecimal"],
      [{ kind: "domain", match: "domain", value: "https://chat.example.com/x" }, "domain name"],
      [{ kind: "domain", match: "domain", value: "*.example.com" }, "domain name"],
      [{ kind: "app", match: "domain", value: "x.com" }, "app rule"],
    ] as const) {
      const r = await rule({ name: "bad", ...body });
      expect(r.status, JSON.stringify(body)).toBe(400);
      expect(r.body.title).toContain(why);
    }
    if (apiHost.includes(".")) expect((await rule({ name: "self", kind: "domain", match: "domain", value: apiHost })).body.title).toContain("Nexus itself");
  });

  it("start in monitor mode; domains always block; audited", async () => {
    const app = await rule({ name: "No Ollama", kind: "app", match: "name", value: "ollama" });
    expect(app.status, JSON.stringify(app.body)).toBe(201);
    expect(app.body).toMatchObject({ mode: "monitor", target: { all: true }, platforms: ["macos", "windows", "linux"], enabled: true, stats: { devices: 0, events_7d: 0 } });
    const dom = await rule({ name: "No shadow AI", kind: "domain", match: "domain", value: "Chat.Example.COM.", mode: "monitor" });
    expect(dom.body).toMatchObject({ value: "chat.example.com", mode: "block" });
    const scoped = await rule({ name: "Contractors: no Cursor", kind: "app", match: "path", value: "/Applications/Cursor.app/", mode: "block", target: { group_ids: [groupId] }, platforms: ["macos"] });
    expect(scoped.status).toBe(201);
    const ev = (await h.call("GET", "/v1/audit/events?type=enforcement.rule_created", { token: admin })).body.data;
    expect(ev).toHaveLength(3);
    expect(ev.find((e: any) => e.target.display === "No shadow AI").details).toMatchObject({ value: "chat.example.com", mode: "block", reason: "Pilot test" });
  });
});

describe("the signed policy", () => {
  it("gives each device the rules for its platform and groups", async () => {
    const m = await policyOf(mac);
    expect(m.sub).toBe(mac.id);
    expect(m.rules.map((r) => r.name).sort()).toEqual(["Contractors: no Cursor", "No Ollama", "No shadow AI"]);
    const w = await policyOf(win);
    expect(w.rules.map((r) => r.name).sort()).toEqual(["No Ollama", "No shadow AI"]); // not in Contractors, and not macOS
    // Each response is newer (the agent refuses older ones), with the same version while rules don't change.
    const again = await policyOf(win);
    expect(again.ts).toBeGreaterThanOrEqual(w.ts);
    expect(again.ver).toBe(w.ver);
  });

  it("changes version when a rule changes, and the device reports what it applied", async () => {
    const before = await policyOf(lab);
    const ollama = (await h.call("GET", "/v1/enforcement/rules", { token: admin })).body.data.find((r: any) => r.name === "No Ollama");
    const r = await h.call("PATCH", `/v1/enforcement/rules/${ollama.id}`, { token: admin, body: { mode: "block" } });
    expect(r.body.mode).toBe("block");
    const after = await policyOf(lab);
    expect(after.ver).not.toBe(before.ver);
    expect(after.rules.find((x) => x.name === "No Ollama")!.mode).toBe("block");

    let st = (await h.call("GET", `/v1/devices/${lab.id}/enforcement`, { token: admin })).body;
    expect(st).toMatchObject({ expected_version: after.ver, in_sync: false });
    await checkin(lab, { enforcement: { version: after.ver, status: "2 app rules (1 blocking), 1 domains blocked", events: [] } });
    st = (await h.call("GET", `/v1/devices/${lab.id}/enforcement`, { token: admin })).body;
    expect(st).toMatchObject({ in_sync: true, status: "2 app rules (1 blocking), 1 domains blocked" });
  });
});

describe("what devices report", () => {
  it("stores events, audits them and raises an alert when a blocked app keeps coming back", async () => {
    const rules = (await h.call("GET", "/v1/enforcement/rules", { token: admin })).body.data;
    const ollama = rules.find((r: any) => r.name === "No Ollama");
    const at = new Date().toISOString();
    const events = [
      { rule_id: ollama.id, action: "terminated", subject: "/usr/local/bin/ollama", user: "sam", count: 6, at },
      { rule_id: "not-a-rule", action: "would_terminate", subject: "/x", user: "", count: 1, at },
      { rule_id: "", action: "failed", detail: "couldn't update the hosts file: permission denied", at },
    ];
    for (let i = 0; i < 5; i++) await checkin(mac, { enforcement: { version: "v", status: "ok", events: i === 0 ? events : [{ ...events[0], count: 1 }] } });
    const list = (await h.call("GET", `/v1/enforcement/events?device_id=${mac.id}`, { token: admin })).body.data;
    expect(list.filter((e: any) => e.action === "terminated")).toHaveLength(5);
    expect(list.find((e: any) => e.action === "would_terminate")).toMatchObject({ rule_id: null, rule_name: "" });
    expect(list.find((e: any) => e.action === "terminated")).toMatchObject({ rule_name: "No Ollama", hostname: "sams-mac", user: "sam" });
    expect((await h.call("GET", "/v1/audit/events?type=device.app_terminated", { token: admin })).body.data).toHaveLength(5);
    expect((await h.call("GET", "/v1/audit/events?type=device.enforcement_failed", { token: admin })).body.data[0]).toMatchObject({ outcome: "failure" });

    await evaluate(h.deps, orgId);
    const alerts = (await h.call("GET", "/v1/alerts?status=all", { token: admin })).body.data;
    expect(alerts.find((a: any) => a.title.includes("Blocked app keeps coming back"))).toBeTruthy();
    expect((await h.call("GET", "/v1/enforcement/rules", { token: admin })).body.data.find((r: any) => r.name === "No Ollama").stats).toEqual({ devices: 1, events_7d: 10 });
  });

  it("drops a malformed report without losing the check-in", async () => {
    const r = await checkin(win, { enforcement: { events: [{ action: "nuke" }] } });
    expect(r.status).toBe(200);
  });

  it("removing a rule takes it out of every device's policy", async () => {
    const dom = (await h.call("GET", "/v1/enforcement/rules", { token: admin })).body.data.find((r: any) => r.kind === "domain");
    expect((await h.call("DELETE", `/v1/enforcement/rules/${dom.id}`, { token: admin })).status).toBe(204);
    expect((await policyOf(win)).rules.map((r) => r.name)).toEqual(["No Ollama"]);
  });
});

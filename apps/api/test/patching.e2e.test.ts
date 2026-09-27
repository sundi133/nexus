import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runPatchPolicies } from "../src/devices/patching.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** OS patching: reported updates, installs as signed commands, the patch policy and the os_updates check. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let helpdesk = "";
let orgId = "";
const devices: Record<string, { d: SoftDevice; id: string }> = {};

async function agentCall(path: string, payload: unknown, d: SoftDevice, enroll = false) {
  const body = JSON.stringify(payload);
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof(path, body, { enroll })}` }, body });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
const posture = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
const checkin = async (name: string, extra: Record<string, unknown> = {}) => (await agentCall("/v1/agent/checkin", { device: { agent_version: "0.2.0" }, posture, ...extra }, devices[name]!.d)).body;
const report = (available: { name: string; version?: string; security: boolean; restart: boolean; upgrade?: boolean }[], error?: string) => ({ inventory: { updates: { checked_at: new Date().toISOString(), available, ...(error ? { error } : {}) } } });
const decode = (jws: string) => JSON.parse(Buffer.from(jws.split(".")[1]!, "base64url").toString());
const row = async (name: string) => (await db.query("SELECT updates_pending, security_updates_pending, updates_pending_since, security_updates_since, updates_error FROM devices WHERE id = $1", [devices[name]!.id])).rows[0];

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  const s = (await h.call("POST", "/v1/signup", { body: { organization_name: "Patch Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body;
  admin = s.token;
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;
  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "all" } })).body.token;
  for (const [name, platform] of [["mac", "macos"], ["linux", "linux"], ["win", "windows"], ["old", "linux"]] as const) {
    const d = await new SoftDevice().init();
    const r = await agentCall("/v1/agent/enroll", { token: t, device: { hostname: name, platform, os_version: "1", agent_version: "0.1.0" } }, d, true);
    d.id = r.body.device_id;
    devices[name] = { d, id: r.body.device_id };
  }
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("OS patching", () => {
  it("keeps each device's pending updates, and since when security ones have waited", async () => {
    await checkin("mac", report([{ name: "macOS Sonoma 14.6.1-23G93", version: "14.6.1", security: true, restart: true }, { name: "Safari", version: "18.0", security: false, restart: false }, { name: "macOS 27", version: "27", security: false, restart: true, upgrade: true }]));
    await checkin("linux", report([{ name: "openssl", version: "3.0.13-0ubuntu3.4", security: true, restart: false }]));
    await checkin("win", report([]));
    await checkin("old"); // an agent too old to report updates
    expect(await row("mac")).toMatchObject({ updates_pending: 2, security_updates_pending: 1 });
    const since = (await row("linux")).security_updates_since as Date;
    expect(since).toBeInstanceOf(Date);

    // The clock keeps running while some are pending, and a failed check doesn't reset it…
    await checkin("linux", report([{ name: "openssl", security: true, restart: false }, { name: "curl", security: true, restart: false }]));
    expect((await row("linux")).security_updates_since).toEqual(since);
    await checkin("linux", report([], "apt-get update: Could not resolve archive.ubuntu.com"));
    expect(await row("linux")).toMatchObject({ security_updates_pending: 2, security_updates_since: since, updates_error: "apt-get update: Could not resolve archive.ubuntu.com" });
    // …and a malformed report is dropped without failing the check-in.
    const bad = await agentCall("/v1/agent/checkin", { device: {}, posture, inventory: { updates: { checked_at: "yesterday", available: "lots" } } }, devices.linux!.d);
    expect(bad.status).toBe(200);
    expect(await row("linux")).toMatchObject({ security_updates_pending: 2 });

    const fleet = (await h.call("GET", "/v1/device-updates", { token: helpdesk })).body;
    expect(fleet.summary).toMatchObject({ devices: 4, reporting: 3, up_to_date: 1, with_security: 2, failing_checks: 1 });
    expect(fleet.data[0]).toMatchObject({ hostname: "linux", security_pending: 2, error: expect.stringContaining("Could not resolve") });
    const one = (await h.call("GET", `/v1/devices/${devices.mac!.id}/updates`, { token: helpdesk })).body;
    expect(one.available.map((u: any) => u.name)).toEqual(["macOS Sonoma 14.6.1-23G93", "Safari", "macOS 27"]); // a major upgrade is shown, not counted
  });

  it("installs on demand as signed commands, only where something is pending", async () => {
    const body = { target: { all: true }, scope: "security", restart: "if_needed", reason: "Patch Tuesday" };
    expect((await h.call("POST", "/v1/device-updates/install", { token: helpdesk, body })).status).toBe(403);
    const r = await h.call("POST", "/v1/device-updates/install", { token: admin, body });
    expect(r.status).toBe(201);
    expect(r.body).toEqual({ queued: 2, skipped_up_to_date: 1, skipped_not_reporting: 1, skipped_in_progress: 0 });
    // Asking again doesn't queue a second install behind the first.
    expect((await h.call("POST", "/v1/device-updates/install", { token: admin, body })).body).toMatchObject({ queued: 0, skipped_in_progress: 2 });

    const cmds = (await checkin("mac")).commands as { id: string; jws: string }[];
    expect(cmds).toHaveLength(1);
    expect(decode(cmds[0]!.jws)).toMatchObject({ act: "updates", sub: devices.mac!.id, args: { scope: "security", restart: "if_needed" } });
    await checkin("mac", { command_results: [{ id: cmds[0]!.id, status: "done", output: "Done.; restarting", data: { summary: "Done.; restarting", restarted: true } }] });
    const one = (await h.call("GET", `/v1/devices/${devices.mac!.id}/updates`, { token: admin })).body;
    expect(one.installs[0]).toMatchObject({ status: "done", output: "Done.; restarting", automatic: false });
    const res = (await db.query("SELECT result FROM device_commands WHERE id = $1", [cmds[0]!.id])).rows[0].result;
    expect(res).toEqual({ summary: "Done.; restarting", restarted: true });
    // The device reports again after installing: nothing pending, the clock stops.
    await checkin("mac", report([]));
    expect(await row("mac")).toMatchObject({ updates_pending: 0, security_updates_pending: 0, security_updates_since: null, updates_pending_since: null });

    const ev = (await db.query("SELECT details FROM audit_events WHERE org_id = $1 AND type = 'device.updates_install' ORDER BY id LIMIT 1", [orgId])).rows[0].details;
    expect(ev).toMatchObject({ automatic: false, scope: "security", reason: "Patch Tuesday", queued: 2 });
  });

  it("the patch policy installs what has waited past its deadline, inside its window", async () => {
    // Clear the manual install still waiting on Linux.
    await db.query("UPDATE device_commands SET status = 'canceled', created_at = now() - interval '1 day' WHERE device_id = $1 AND action = 'updates'", [devices.linux!.id]);
    const policy = { enabled: true, scope: "security", deadline_days: 2, restart: "never", window_start: 0, window_end: 0, timezone: "Mars/Olympus" };
    expect((await h.call("PUT", "/v1/patch-policy", { token: admin, body: policy })).body.code).toBe("invalid_timezone");
    expect((await h.call("PUT", "/v1/patch-policy", { token: helpdesk, body: { ...policy, timezone: "UTC" } })).status).toBe(403);
    expect((await h.call("PUT", "/v1/patch-policy", { token: admin, body: { ...policy, timezone: "Europe/Berlin" } })).status).toBe(200);

    // Not yet due: seen today, deadline two days.
    await checkin("linux", report([{ name: "openssl", security: true, restart: false }]));
    await runPatchPolicies(h.deps);
    expect((await db.query("SELECT count(*)::int AS n FROM device_commands WHERE device_id = $1 AND action = 'updates' AND status = 'queued'", [devices.linux!.id])).rows[0].n).toBe(0);

    // Three days later it is, unless outside the window.
    await db.query("UPDATE devices SET security_updates_since = now() - interval '3 days' WHERE id = $1", [devices.linux!.id]);
    const hour = Number(new Intl.DateTimeFormat("en-GB", { hour: "numeric", hourCycle: "h23", timeZone: "Europe/Berlin" }).format(new Date()));
    await h.call("PUT", "/v1/patch-policy", { token: admin, body: { ...policy, timezone: "Europe/Berlin", window_start: (hour + 2) % 24, window_end: (hour + 4) % 24 } });
    await runPatchPolicies(h.deps);
    expect((await db.query("SELECT count(*)::int AS n FROM device_commands WHERE device_id = $1 AND action = 'updates' AND status = 'queued'", [devices.linux!.id])).rows[0].n).toBe(0);

    await h.call("PUT", "/v1/patch-policy", { token: admin, body: { ...policy, timezone: "Europe/Berlin", window_start: hour, window_end: (hour + 1) % 24 } });
    await runPatchPolicies(h.deps);
    const cmds = (await checkin("linux")).commands as { id: string; jws: string }[];
    expect(cmds).toHaveLength(1);
    expect(decode(cmds[0]!.jws)).toMatchObject({ act: "updates", args: { scope: "security", restart: "never" } });
    const fleet = (await h.call("GET", "/v1/device-updates", { token: admin })).body;
    expect(fleet.data.find((d: any) => d.hostname === "linux")).toMatchObject({ overdue: true, last_install: { automatic: true, status: "sent" } });

    // A failed install isn't retried in a loop: not again within 12 hours.
    await checkin("linux", { command_results: [{ id: cmds[0]!.id, status: "failed", output: "dpkg was interrupted" }] });
    await runPatchPolicies(h.deps);
    expect((await checkin("linux")).commands ?? []).toEqual([]);
    const ev = (await db.query("SELECT actor_display, details FROM audit_events WHERE org_id = $1 AND type = 'device.updates_install' ORDER BY id DESC LIMIT 1", [orgId])).rows[0];
    expect(ev).toMatchObject({ actor_display: "Patch policy", details: { automatic: true, devices: 1 } });
  });

  it("the os_updates check fails devices whose security updates wait too long", async () => {
    const r = await h.call("PUT", "/v1/device-policies/os_updates", { token: admin, body: { enabled: true, mode: "enforce", params: { max_days: 2 } } });
    expect(r.status).toBe(200);
    const checks = async (name: string) => (await h.call("GET", `/v1/devices/${devices[name]!.id}`, { token: admin })).body.checks.find((c: any) => c.key === "os_updates");
    expect(await checks("linux")).toMatchObject({ status: "fail", detail: "1 security update pending for 3 days (policy allows 2 days)" });
    expect(await checks("mac")).toMatchObject({ status: "pass", detail: "No security updates pending" });
    expect(await checks("old")).toMatchObject({ status: "unknown" });
    expect((await h.call("GET", `/v1/devices/${devices.linux!.id}`, { token: admin })).body.compliance).toBe("non_compliant");
  });

  it("third-party apps: counted apart from OS updates, installed on request and by the policy", async () => {
    // Windows reports two outdated apps and no OS updates; a failed app check keeps the counts.
    await checkin("win", { inventory: { updates: { checked_at: new Date().toISOString(), available: [
      { name: "Google Chrome", app_id: "Google.Chrome", current: "120.0", version: "121.0", security: false, restart: false, third_party: true },
      { name: "Zoom", app_id: "Zoom.Zoom", current: "5.16", version: "6.0", security: false, restart: false, third_party: true },
    ] } } });
    expect((await db.query("SELECT updates_pending, third_party_pending, third_party_since IS NOT NULL AS since FROM devices WHERE id = $1", [devices.win!.id])).rows[0]).toEqual({ updates_pending: 0, third_party_pending: 2, since: true });
    await checkin("win", { inventory: { updates: { checked_at: new Date().toISOString(), available: [], third_party_error: "winget: source unavailable" } } });
    expect((await db.query("SELECT third_party_pending FROM devices WHERE id = $1", [devices.win!.id])).rows[0].third_party_pending).toBe(2);
    const row = (await h.call("GET", "/v1/device-updates", { token: admin })).body.data.find((d: any) => d.hostname === "win");
    expect(row).toMatchObject({ pending: 0, apps_pending: 2 });

    // Without apps: nothing to do on Windows. With apps: an apps-only command.
    expect((await h.call("POST", "/v1/device-updates/install", { token: admin, body: { target: { device_ids: [devices.win!.id] }, reason: "Browser CVE" } })).body.queued).toBe(0);
    expect((await h.call("POST", "/v1/device-updates/install", { token: admin, body: { target: { device_ids: [devices.win!.id] }, apps: true, reason: "Browser CVE" } })).body.queued).toBe(1);
    const cmd = ((await checkin("win")).commands as { jws: string }[])[0]!;
    expect(decode(cmd.jws)).toMatchObject({ act: "updates", args: { scope: "none", third_party: true } });
    await db.query("UPDATE device_commands SET status = 'done', created_at = now() - interval '1 day' WHERE device_id = $1 AND action = 'updates'", [devices.win!.id]);

    // The policy keeps apps up to date too, once they've waited past the deadline.
    await h.call("PUT", "/v1/patch-policy", { token: admin, body: { enabled: true, scope: "security", deadline_days: 1, restart: "never", window_start: 0, window_end: 0, timezone: "UTC", third_party: true } });
    await db.query("UPDATE devices SET third_party_since = now() - interval '2 days' WHERE id = $1", [devices.win!.id]);
    await runPatchPolicies(h.deps);
    const auto = ((await checkin("win")).commands as { jws: string }[])[0]!;
    expect(decode(auto.jws)).toMatchObject({ args: { scope: "none", third_party: true } });
  });
});


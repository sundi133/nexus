import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Scripts on devices: the library, runs as signed commands, and each device's result. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let helpdesk = "";
const devices: Record<string, { d: SoftDevice; id: string }> = {};

async function agentCall(path: string, payload: unknown, d: SoftDevice, enroll = false) {
  const body = JSON.stringify(payload);
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await d.proof(path, body, { enroll })}` }, body });
  return (await res.json()) as Record<string, any>;
}
const posture = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
const checkin = (name: string, extra: Record<string, unknown> = {}) => agentCall("/v1/agent/checkin", { device: { agent_version: "0.1.0" }, posture, ...extra }, devices[name]!.d);
const decode = (jws: string) => JSON.parse(Buffer.from(jws.split(".")[1]!, "base64url").toString());

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Scripts Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;
  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "all" } })).body.token;
  for (const [name, platform] of [["mac", "macos"], ["linux", "linux"], ["win", "windows"]] as const) {
    const d = await new SoftDevice().init();
    const r = await agentCall("/v1/agent/enroll", { token: t, device: { hostname: name, platform, os_version: "1", agent_version: "0.1.0" } }, d, true);
    d.id = r.device_id;
    devices[name] = { d, id: r.device_id };
  }
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("device scripts", () => {
  let scriptId = "";
  let runId = "";

  it("are for owners and admins only", async () => {
    expect((await h.call("GET", "/v1/device-scripts", { token: helpdesk })).status).toBe(403);
    const s = await h.call("POST", "/v1/device-scripts", { token: admin, body: { name: "Disk usage", shell: "bash", body: "df -h /" } });
    expect(s.status).toBe(201);
    scriptId = s.body.id;
  });

  it("run on the devices whose OS can run them, as signed commands carrying the script", async () => {
    const r = await h.call("POST", "/v1/script-runs", { token: admin, body: { script_id: scriptId, reason: "Check free space", target: { all: true }, timeout_seconds: 60 } });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ devices: 2, skipped_incompatible: 1, pending: 2 }); // bash: not on Windows
    runId = r.body.id;
    const cmds = (await checkin("mac")).commands as { id: string; jws: string }[];
    const claims = decode(cmds[0]!.jws);
    expect(claims).toMatchObject({ act: "script", args: { shell: "bash", script: "df -h /", timeout_seconds: 60 } });
    expect((await checkin("win")).commands ?? []).toEqual([]);

    // Each device returns its exit code and output.
    await checkin("mac", { command_results: [{ id: cmds[0]!.id, status: "done", output: "exit 0 in 0.1s", data: { exit_code: 0, output: "/dev/disk1 50% /", truncated: false, timed_out: false, duration_ms: 120 } }] });
    const linuxCmd = ((await checkin("linux")).commands as { id: string }[])[0]!;
    await checkin("linux", { command_results: [{ id: linuxCmd.id, status: "failed", output: "exit 1 in 0.1s", data: { exit_code: 1, output: "df: /: no such device", truncated: false, timed_out: false, duration_ms: 90 } }] });

    const run = (await h.call("GET", `/v1/script-runs/${runId}`, { token: admin })).body;
    expect(run).toMatchObject({ succeeded: 1, failed: 1, pending: 0, body: "df -h /" });
    expect(run.results.map((x: any) => [x.hostname, x.exit_code, x.output])).toEqual([
      ["linux", 1, "df: /: no such device"],
      ["mac", 0, "/dev/disk1 50% /"],
    ]);
  });

  it("are audited with the script's hash, and a one-off script works too", async () => {
    const ev = (await db.query("SELECT details FROM audit_events WHERE type = 'device.script_run' AND target_id = $1", [runId])).rows[0].details;
    expect(ev).toMatchObject({ shell: "bash", devices: 2, sha256: expect.stringMatching(/^[0-9a-f]{64}$/) });
    const r = await h.call("POST", "/v1/script-runs", { token: admin, body: { script: { name: "Hostname", shell: "powershell", body: "hostname" }, reason: "Inventory", target: { device_ids: [devices.win!.id, devices.mac!.id] } } });
    expect(r.body).toMatchObject({ devices: 1, skipped_incompatible: 1 });
    expect((await h.call("POST", "/v1/script-runs", { token: admin, body: { script_id: scriptId, reason: "x", target: {} } })).status).toBe(400);
  });
});

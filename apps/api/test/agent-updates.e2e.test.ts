import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { releaseStore, statement } from "../src/devices/releases.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/**
 * Agent self-update (DEV-07): signed releases, staged rollouts (canary → 10%
 * → all), offers in check-ins, reported results, halting on failure.
 */

const releasesDir = mkdtempSync(join(tmpdir(), "nexus-releases-"));
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const rawPub = publicKey.export({ format: "der", type: "spki" }).subarray(12);
const keyId = createHash("sha256").update(rawPub).digest("hex").slice(0, 16);
const releaseKeys = rawPub.toString("base64");

/** Writes a release like `nexus-release sign` does. `tamper` corrupts the file after signing. */
function publish(version: string, platforms: [string, string][], opts: { tamper?: boolean; foreignKey?: boolean } = {}) {
  const dir = join(releasesDir, version);
  mkdirSync(dir, { recursive: true });
  const signer = opts.foreignKey ? generateKeyPairSync("ed25519").privateKey : privateKey;
  const artifacts = platforms.map(([os, arch]) => {
    const file = `nexus-agent-${os}-${arch}${os === "windows" ? ".exe" : ""}`;
    const content = Buffer.from(`binary ${version} ${os}/${arch}`);
    const sha256 = createHash("sha256").update(content).digest("hex");
    writeFileSync(join(dir, file), opts.tamper ? Buffer.from(`evil!! ${version} ${os}/${arch}`) : content);
    return { os, arch, file, sha256, size: content.length, key_id: keyId, signature: sign(null, statement(version, os, arch, sha256, content.length), signer).toString("base64") };
  });
  writeFileSync(join(dir, "release.json"), JSON.stringify({ version, published_at: new Date().toISOString(), notes: `Release ${version}`, artifacts }));
  releaseStore({ agentReleasesDir: releasesDir, agentReleaseKeys: releaseKeys }).refresh();
}

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";
const macs: SoftDevice[] = [];
const names = new Map<string, string>();
let linux: SoftDevice;

async function agentCall(path: string, payload: unknown, device: SoftDevice, enroll = false) {
  const raw = JSON.stringify(payload);
  const res = await h.app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `NexusDevice ${await device.proof(path, raw, { enroll })}` },
    body: raw,
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
async function checkin(d: SoftDevice, version: string, extra: Record<string, unknown> = {}) {
  const posture = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
  const r = await agentCall("/v1/agent/checkin", { device: { agent_version: version }, posture, ...extra }, d);
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  return r.body as { update: null | { version: string; url: string; sha256: string; size: number; key_id: string; signature: string } };
}
const getStatus = async () => (await h.call("GET", "/v1/agent-updates", { token: admin })).body;
const act = (id: string, action: string) => h.call("POST", `/v1/agent-updates/rollouts/${id}/actions`, { token: admin, body: { action } });

beforeAll(async () => {
  publish("0.2.0", [["darwin", "arm64"], ["windows", "amd64"]]);
  publish("0.1.9", [["darwin", "arm64"]], { tamper: true }); // file doesn't match its signature
  publish("0.1.8", [["darwin", "arm64"]], { foreignKey: true }); // signed by someone else
  h = await bootApp({ agentReleasesDir: releasesDir, agentReleaseKeys: releaseKeys });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const signup = await h.call("POST", "/v1/signup", { body: { organization_name: "Umbrella", email: uniqueEmail("alice"), password: PASSWORD, given_name: "Alice" } });
  admin = signup.body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  // Start with automatic rollouts off to drive the stages by hand.
  expect((await h.call("PUT", "/v1/agent-updates/settings", { token: admin, body: { auto_rollout: false, advance_after_hours: 0 } })).status).toBe(200);

  const token = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "fleet", max_uses: 10 } })).body.token;
  const enroll = async (hostname: string, platform: string, arch: string) => {
    const d = await new SoftDevice().init();
    const r = await agentCall("/v1/agent/enroll", { token, device: { hostname, platform, arch, agent_version: "0.1.0" } }, d, true);
    expect(r.status).toBe(201);
    d.id = r.body.device_id;
    names.set(d.id, hostname);
    return d;
  };
  for (const n of ["mac-a", "mac-b", "mac-c"]) macs.push(await enroll(n, "macos", "arm64"));
  linux = await enroll("build-box", "linux", "amd64");
  for (const d of [...macs, linux]) await checkin(d, "0.1.0");
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("releases", () => {
  it("lists only releases whose signatures and files check out", async () => {
    const s = await getStatus();
    expect(s.release_keys_configured).toBe(true);
    expect(s.releases.map((r: { version: string }) => r.version)).toEqual(["0.2.0"]);
    expect(s.latest).toMatchObject({ version: "0.2.0", platforms: ["darwin/arm64", "windows/amd64"] });
    expect(s.fleet).toEqual([{ version: "0.1.0", devices: 4 }]);
    expect(s.rollout).toBeNull(); // auto-rollout is off
  });

  it("serves the exact signed bytes", async () => {
    const res = await h.app.request("/v1/agent/releases/0.2.0/nexus-agent-darwin-arm64");
    expect(res.status).toBe(200);
    expect(Buffer.from(await res.arrayBuffer()).toString()).toBe("binary 0.2.0 darwin/arm64");
    expect((await h.app.request("/v1/agent/releases/0.1.9/nexus-agent-darwin-arm64")).status).toBe(404);
    expect((await h.app.request("/v1/agent/releases/0.2.0/..%2Frelease.json")).status).toBe(404);
  });
});

describe("staged rollout", () => {
  let rolloutId = "";
  let canary: SoftDevice;
  let rest: SoftDevice[];

  it("only admins roll out, and only known releases", async () => {
    const email = uniqueEmail("helper");
    expect((await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } })).status).toBe(201);
    const helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    expect((await h.call("POST", "/v1/agent-updates/rollouts", { token: helpdesk, body: { version: "0.2.0" } })).status).toBe(403);
    expect((await h.call("POST", "/v1/agent-updates/rollouts", { token: admin, body: { version: "0.1.9" } })).status).toBe(404);
    expect((await h.call("POST", "/v1/agent-updates/rollouts", { token: admin, body: { version: "0.2.0", canary_device_ids: [linux.id] } })).status).toBe(400); // no linux build
  });

  it("starts with the canary only, offering a signed update", async () => {
    canary = macs[1]!;
    rest = macs.filter((m) => m !== canary);
    const r = await h.call("POST", "/v1/agent-updates/rollouts", { token: admin, body: { version: "0.2.0", canary_device_ids: [canary.id] } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    rolloutId = r.body.rollout.id;
    expect(r.body.rollout).toMatchObject({ version: "0.2.0", stage: "canary", status: "active", started_by: expect.stringContaining("alice") });

    const offer = (await checkin(canary, "0.1.0")).update!;
    expect(offer).toMatchObject({ version: "0.2.0", url: "/v1/agent/releases/0.2.0/nexus-agent-darwin-arm64", key_id: keyId });
    // What the agent checks, with its compiled-in key.
    const pub = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawPub]), format: "der", type: "spki" });
    expect(verify(null, statement(offer.version, "darwin", "arm64", offer.sha256, offer.size), pub, Buffer.from(offer.signature, "base64"))).toBe(true);

    for (const d of [...rest, linux]) expect((await checkin(d, "0.1.0")).update).toBeNull();
  });

  it("tracks the canary's update, then widens stage by stage", async () => {
    // The new binary checks in with its version, then reports the verified install.
    await checkin(canary, "0.2.0");
    expect((await checkin(canary, "0.2.0", { update_result: { version: "0.2.0", state: "installed" } })).update).toBeNull();
    let s = await getStatus();
    expect(s.rollout.stages[0]).toEqual({ stage: "canary", devices: 1, updated: 1, failed: 0 });
    expect(s.rollout.devices.find((d: { id: string }) => d.id === canary.id)).toMatchObject({ ring: "canary", state: "updated" });
    expect(s.rollout.devices.find((d: { id: string }) => d.id === linux.id)).toMatchObject({ state: "unsupported" });

    expect((await act(rolloutId, "advance")).body.rollout.stage).toBe("early");
    s = (await act(rolloutId, "advance")).body;
    expect(s.rollout.stage).toBe("all");
    for (const d of rest) expect((await checkin(d, "0.1.0")).update?.version).toBe("0.2.0");
    expect((await checkin(linux, "0.1.0")).update).toBeNull();
    // Never a downgrade.
    expect((await checkin(rest[0]!, "0.3.0")).update).toBeNull();
    await checkin(rest[0]!, "0.1.0");
  });

  it("halts on the first rollback and tells admins why", async () => {
    const [bad, good] = rest as [SoftDevice, SoftDevice];
    await checkin(bad, "0.1.0", { update_result: { version: "0.2.0", state: "rolled_back", error: "0.2.0 restarted 3 times without checking in" } });
    const s = await getStatus();
    expect(s.rollout).toMatchObject({ status: "halted" });
    expect(s.rollout.halted_reason).toBe(`${names.get(bad.id)} rolled back 0.2.0: 0.2.0 restarted 3 times without checking in`);
    // Nobody else is offered it while halted.
    expect((await checkin(good, "0.1.0")).update).toBeNull();
    const inbox = await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin });
    expect(inbox.body.data[0]).toMatchObject({ title: "Agent 0.2.0 rollout halted", severity: "warning", link: "/agent-updates" });
    const audit = await h.call("GET", "/v1/audit/events?type=device.agent_update_failed", { token: admin });
    expect(audit.body.data[0]).toMatchObject({ outcome: "failure", target: { display: names.get(bad.id) } });
  });

  it("resumes without retrying the device that failed, then completes", async () => {
    const [bad, good] = rest as [SoftDevice, SoftDevice];
    expect((await act(rolloutId, "resume")).body.rollout.status).toBe("active");
    expect((await checkin(bad, "0.1.0")).update).toBeNull();
    expect((await checkin(good, "0.1.0")).update?.version).toBe("0.2.0");
    await checkin(good, "0.2.0");
    const s = await getStatus();
    expect(s.rollout.status).toBe("completed"); // every supported device updated or gave up
    expect(s.fleet).toEqual([
      { version: "0.2.0", devices: 2 },
      { version: "0.1.0", devices: 2 },
    ]);
    expect((await act(rolloutId, "pause")).status).toBe(409);
  });
});

describe("automatic rollouts", () => {
  it("start by themselves for a new release and advance after the wait", async () => {
    publish("0.3.0", [["darwin", "arm64"]]);
    await h.call("PUT", "/v1/agent-updates/settings", { token: admin, body: { auto_rollout: true, advance_after_hours: 24 } });
    const first = await checkin(macs[0]!, "0.2.0");
    let s = await getStatus();
    expect(s.rollout).toMatchObject({ version: "0.3.0", stage: "canary", status: "active", started_by: "Nexus (automatic)" });
    const canaryId = s.rollout.devices.find((d: { ring: string }) => d.ring === "canary").id;
    expect(s.rollout.next_advance_at).not.toBeNull();
    if (canaryId !== macs[0]!.id) expect(first.update).toBeNull();

    // The canary updates healthily; a day later the rollout widens by itself.
    await owner.query("UPDATE devices SET agent_version = '0.3.0' WHERE id = $1", [canaryId]);
    await owner.query("UPDATE agent_rollouts SET stage_started_at = now() - interval '25 hours' WHERE org_id = $1 AND version = '0.3.0'", [orgId]);
    s = await getStatus();
    expect(s.rollout.stage).toBe("early");
    const audit = await h.call("GET", "/v1/audit/events?type=agent.rollout_advanced", { token: admin });
    expect(audit.body.data[0]).toMatchObject({ actor: { display: "Nexus" }, details: { from: "canary", to: "early" } });
  });

  it("isn't restarted after an admin cancels it", async () => {
    const s = await getStatus();
    expect((await act(s.rollout.id, "cancel")).body.rollout.status).toBe("cancelled");
    await checkin(macs[0]!, "0.2.0");
    expect((await getStatus()).rollout).toMatchObject({ version: "0.3.0", status: "cancelled" });
  });
});

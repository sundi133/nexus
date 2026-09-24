import { exportJWK, generateKeyPair, SignJWT, type CryptoKey as JoseKey } from "jose";
import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** A software device agent: P-256 key + signed proofs, exactly what the Go agent sends. */
class SoftDevice {
  id = "";
  private key!: { privateKey: JoseKey; publicKey: JoseKey };
  async init() {
    this.key = await generateKeyPair("ES256", { extractable: true });
    return this;
  }
  async proof(path: string, body: string, opts: { method?: string; iatOffset?: number; jti?: string; enroll?: boolean; bodyForHash?: string } = {}) {
    const iat = Math.floor(Date.now() / 1000) + (opts.iatOffset ?? 0);
    const header = opts.enroll
      ? { alg: "ES256", typ: "nexus-device+jwt", jwk: await exportJWK(this.key.publicKey) }
      : { alg: "ES256", typ: "nexus-device+jwt", kid: this.id };
    return new SignJWT({
      htm: opts.method ?? "POST",
      htu: path,
      bsh: createHash("sha256").update(opts.bodyForHash ?? body).digest("base64url"),
      jti: opts.jti ?? randomUUID(),
    })
      .setProtectedHeader(header)
      .setAudience("nexus-agent")
      .setIssuedAt(iat)
      .setExpirationTime(iat + 120)
      .sign(this.key.privateKey);
  }
}

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let sam = "";
let samId = "";

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
const info = { hostname: "sams-mbp", platform: "macos", os_name: "macOS", os_version: "15.1", os_build: "24B83", arch: "arm64", model: "MacBookPro18,3", serial: "C02XYZ", agent_version: "0.1.0" };
const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 300 }, system_integrity: { status: "on" } };

async function enroll(device: SoftDevice, token: string, extra: Partial<typeof info> = {}) {
  const payload = { token, device: { ...info, ...extra } };
  const r = await agentCall("/v1/agent/enroll", payload, await device.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  if (r.status === 201) device.id = r.body.device_id;
  return r;
}
async function checkin(device: SoftDevice, posture: unknown = healthy, extra: Record<string, unknown> = {}) {
  const payload = { device: { agent_version: "0.1.0" }, posture, inventory: { console_user: "sam", memory_bytes: 17179869184 }, ...extra };
  return agentCall("/v1/agent/checkin", payload, await device.proof("/v1/agent/checkin", JSON.stringify(payload)));
}

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Wayne Enterprises", email: uniqueEmail("lucius"), password: PASSWORD, given_name: "Lucius" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const email = uniqueEmail("sam");
  samId = (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Sam", password: PASSWORD } })).body.id;
  sam = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
});
afterAll(() => h.close());

describe("device enrollment", () => {
  let token = "";

  it("admins create enrollment tokens with install commands", async () => {
    const r = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "Laptop rollout", max_uses: 2 } });
    expect(r.status).toBe(201);
    token = r.body.token;
    expect(r.body.commands.macos).toBe(`sudo nexus-agent enroll --server http://localhost:8080 --token ${token}`);
    const list = await h.call("GET", "/v1/devices/enrollment-tokens", { token: admin });
    expect(list.status).toBe(200); // not swallowed by /v1/devices/{id}
    expect(list.body.data[0]).toMatchObject({ name: "Laptop rollout", uses: 0, max_uses: 2 });
    expect(JSON.stringify(list.body)).not.toContain(token);
  });

  it("enrolls a device that proves possession of its key", async () => {
    const d = await new SoftDevice().init();
    const r = await enroll(d, token);
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body).toMatchObject({ organization: "Wayne Enterprises", checkin_interval_seconds: 60 });
    const again = await enroll(d, token);
    expect(again.body.code).toBe("already_enrolled");
  });

  it("rejects bad tokens, missing proofs and exhausted tokens", async () => {
    expect((await enroll(await new SoftDevice().init(), "nxe_nope")).body.code).toBe("invalid_enrollment_token");
    const noProof = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, device: info }) });
    expect(noProof.status).toBe(401);
    // max_uses = 2: one used above; the duplicate attempt above consumed nothing (rolled back); one more succeeds, then it's used up.
    expect((await enroll(await new SoftDevice().init(), token)).status).toBe(201);
    expect((await enroll(await new SoftDevice().init(), token)).body.code).toBe("invalid_enrollment_token");
  });
});

describe("check-ins and compliance", () => {
  const device = new SoftDevice();

  beforeAll(async () => {
    await device.init();
    const personal = await h.call("POST", "/v1/me/devices/enrollment-token", { token: sam });
    expect(personal.status).toBe(201);
    expect((await enroll(device, personal.body.token)).status).toBe(201);
  });

  it("a healthy device becomes compliant and is assigned to the person who enrolled it", async () => {
    const r = await checkin(device);
    expect(r.body).toMatchObject({ compliance: "compliant", checkin_interval_seconds: 60 });
    const d = await h.call("GET", `/v1/devices/${device.id}`, { token: admin });
    expect(d.body).toMatchObject({ hostname: "sams-mbp", compliance: "compliant", online: true, primary_user: { id: samId } });
    // A check-in that only sends agent_version must not wipe the facts from enrollment.
    expect(d.body).toMatchObject({ os_version: "15.1", model: "MacBookPro18,3", serial: "C02XYZ" });
    expect(d.body.checks.map((c: { key: string; status: string }) => `${c.key}:${c.status}`)).toEqual([
      "disk_encryption:pass",
      "firewall:pass",
      "screen_lock:pass",
      "os_version:pass",
      "system_integrity:pass",
    ]);
  });

  it("turning FileVault off makes it non-compliant, explains why, and tells the owner", async () => {
    const r = await checkin(device, { ...healthy, disk_encryption: { status: "off" } });
    expect(r.body.compliance).toBe("non_compliant");
    const mine = await h.call("GET", "/v1/me/devices", { token: sam });
    const check = mine.body.data[0].checks.find((c: { key: string }) => c.key === "disk_encryption");
    expect(check).toMatchObject({ status: "fail", detail: "FileVault is off", fix: expect.stringContaining("FileVault") });
    const inbox = await h.call("GET", "/v1/me/notifications", { token: sam });
    expect(inbox.body.data[0]).toMatchObject({ category: "device.noncompliant", title: "sams-mbp needs attention", body: "FileVault is off" });
    const audit = await h.call("GET", "/v1/audit/events?type=device.compliance_changed", { token: admin });
    expect(audit.body.data[0].details).toMatchObject({ from: "compliant", to: "non_compliant" });
    const list = await h.call("GET", "/v1/devices?compliance=non_compliant", { token: admin });
    expect(list.body.data.map((x: { id: string }) => x.id)).toContain(device.id);
  });

  it("policy changes re-evaluate every device immediately", async () => {
    const off = await h.call("PUT", "/v1/device-policies/disk_encryption", { token: admin, body: { enabled: false } });
    expect(off.body.reevaluated.changed).toBeGreaterThanOrEqual(1);
    expect((await h.call("GET", `/v1/devices/${device.id}`, { token: admin })).body.compliance).toBe("compliant");
    const bad = await h.call("PUT", "/v1/device-policies/screen_lock", { token: admin, body: { enabled: true, params: { max_delay_minutes: 999 } } });
    expect(bad.status).toBe(400);
    const strict = await h.call("PUT", "/v1/device-policies/os_version", { token: admin, body: { enabled: true, params: { minimum: { macos: "16.0", windows: "", linux: "" } } } });
    expect(strict.status).toBe(200);
    const d = await h.call("GET", `/v1/devices/${device.id}`, { token: admin });
    expect(d.body.checks.find((c: { key: string }) => c.key === "os_version")).toMatchObject({ status: "fail", detail: "15.1 is older than the required 16.0" });
  });

  it("unknown readings are never treated as compliant", async () => {
    await h.call("PUT", "/v1/device-policies/os_version", { token: admin, body: { enabled: true, params: { minimum: { macos: "14.0", windows: "", linux: "" } } } });
    const r = await checkin(device, { ...healthy, firewall: { status: "unknown" } });
    expect(r.body.compliance).toBe("unknown");
  });
});

describe("device request signatures", () => {
  const device = new SoftDevice();
  const payload = { device: {}, posture: healthy };
  const raw = JSON.stringify(payload);

  beforeAll(async () => {
    await device.init();
    const t = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "sig tests" } });
    await enroll(device, t.body.token);
  });

  it("rejects a replayed proof", async () => {
    const proof = await device.proof("/v1/agent/checkin", raw);
    expect((await agentCall("/v1/agent/checkin", payload, proof)).status).toBe(200);
    expect((await agentCall("/v1/agent/checkin", payload, proof)).body.code).toBe("replayed_device_proof");
  });

  it("rejects proofs for another path, a tampered body, stale timestamps or another key", async () => {
    expect((await agentCall("/v1/agent/checkin", payload, await device.proof("/v1/agent/enroll", raw))).body.code).toBe("invalid_device_proof");
    expect((await agentCall("/v1/agent/checkin", payload, await device.proof("/v1/agent/checkin", raw, { bodyForHash: raw.replace("on", "off") }))).body.code).toBe("invalid_device_proof");
    expect((await agentCall("/v1/agent/checkin", payload, await device.proof("/v1/agent/checkin", raw, { iatOffset: -900 }))).status).toBe(401);
    const impostor = await new SoftDevice().init();
    impostor.id = device.id; // claims to be the device, signs with a different key
    expect((await agentCall("/v1/agent/checkin", payload, await impostor.proof("/v1/agent/checkin", raw))).body.code).toBe("invalid_device_proof");
  });

  it("a removed device is told it's no longer enrolled", async () => {
    expect((await h.call("DELETE", `/v1/devices/${device.id}`, { token: admin })).status).toBe(204);
    expect((await checkin(device)).body.code).toBe("device_not_enrolled");
  });

  it("refuses oversized bodies before doing any work", async () => {
    const res = await h.app.request("/v1/agent/checkin", { method: "POST", headers: { "content-type": "application/json", authorization: "NexusDevice x" }, body: "x".repeat(300 * 1024) });
    expect(res.status).toBe(413);
  });

  it("isolates tenants", async () => {
    const other = (await h.call("POST", "/v1/signup", { body: { organization_name: "LexCorp", email: uniqueEmail("lex"), password: PASSWORD, given_name: "Lex" } })).body.token;
    expect((await h.call("GET", "/v1/devices", { token: other })).body.data).toEqual([]);
  });
});

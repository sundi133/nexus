import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { webcrypto } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build, FakeMac, parse } from "./fake-mac.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Nexus as an Apple MDM server, driven by a simulated Mac that signs like a real one. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let apns: http2.Http2Server;
const pushes: { path: string; topic: string; body: string }[] = [];
let admin = "";
let helpdesk = "";
let orgId = "";
const TOPIC = "com.apple.mgmt.External.0f1e2d3c-0000-4000-8000-00000000abcd";
const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;
let appleCa: { cert: x509.X509Certificate; keys: webcrypto.CryptoKeyPair };

/** What Apple's portal does with a vendor-signed CSR: a certificate for the CSR's key, with the MDM topic. */
async function appleIssues(csrPem: string, topic = TOPIC) {
  const csr = new x509.Pkcs10CertificateRequest(csrPem);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: "0a",
    subject: `0.9.2342.19200300.100.1.1=${topic}, CN=APSP:0f1e2d3c, C=US`,
    issuer: appleCa.cert.subject,
    notBefore: new Date(Date.now() - 1000),
    notAfter: new Date(Date.now() + 365 * 86_400_000),
    signingAlgorithm: ALG,
    publicKey: await csr.publicKey.export(),
    signingKey: appleCa.keys.privateKey,
  });
  return cert.toString("pem");
}

async function device(mac: FakeMac, url: "checkin" | "connect", msg: Record<string, unknown>, opts: { signAs?: { certPem: string; keyPem: string }; unsigned?: boolean } = {}) {
  const body = build({ UDID: mac.udid, ...msg });
  const res = await h.app.request(`/mdm/apple/${url}`, { method: "PUT", headers: { "content-type": "application/x-apple-aspen-mdm", ...(opts.unsigned ? {} : { "mdm-signature": mac.sign(body, opts.signAs) }) }, body });
  const text = await res.text();
  return { status: res.status, body: res.headers.get("content-type")?.includes("xml") ? parse(text) : text ? JSON.parse(text) : null };
}
const idle = (mac: FakeMac) => device(mac, "connect", { Status: "Idle" });
const ack = (mac: FakeMac, id: string, extra: Record<string, unknown> = {}) => device(mac, "connect", { Status: "Acknowledged", CommandUUID: id, ...extra });

async function enroll(url: string, serial?: string) {
  const res = await h.app.request(new URL(url).pathname);
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toBe("application/x-apple-aspen-config");
  const mac = new FakeMac(Buffer.from(await res.arrayBuffer()), undefined, serial);
  expect((await device(mac, "checkin", { MessageType: "Authenticate", Topic: TOPIC, SerialNumber: mac.serial, Model: "Mac15,13", ModelName: "MacBook Air", OSVersion: "14.5" })).status).toBe(200);
  expect((await device(mac, "checkin", { MessageType: "TokenUpdate", Topic: TOPIC, Token: Buffer.from("a1b2c3d4", "hex"), PushMagic: "magic-1", UnlockToken: Buffer.from("unlock") })).status).toBe(200);
  return mac;
}

beforeAll(async () => {
  apns = http2.createServer();
  apns.on("stream", (stream: http2.ServerHttp2Stream, headers) => {
    let body = "";
    stream.on("data", (c) => (body += c));
    stream.on("end", () => {
      pushes.push({ path: String(headers[":path"]), topic: String(headers["apns-topic"]), body });
      stream.respond({ ":status": 200 });
      stream.end();
    });
  });
  await new Promise<void>((r) => apns.listen(0, "127.0.0.1", r));
  h = await bootApp({ appleMdmPushUrl: `http://127.0.0.1:${(apns.address() as AddressInfo).port}` });
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Mac Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  appleCa = { keys, cert: await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=Apple Test CA", notBefore: new Date(Date.now() - 1000), notAfter: new Date(Date.now() + 86_400_000 * 400), signingAlgorithm: ALG, keys }) };
});
afterAll(async () => {
  apns.close();
  await db.end();
  await h.close();
});

describe("Apple MDM", () => {
  let link = "";
  let mac: FakeMac;

  it("sets up the push certificate from Nexus's own CSR", async () => {
    expect((await h.call("GET", "/v1/apple-mdm", { token: admin })).body).toMatchObject({ ready: false, push: null });
    expect((await h.call("POST", "/v1/apple-mdm/enrollment-links", { token: admin, body: { name: "Office Macs" } })).body.code).toBe("mdm_not_ready");
    expect((await h.call("POST", "/v1/apple-mdm/push-csr", { token: helpdesk })).status).toBe(403);
    const { csr } = (await h.call("POST", "/v1/apple-mdm/push-csr", { token: admin })).body;
    expect(csr).toContain("BEGIN CERTIFICATE REQUEST");
    // A certificate for some other key is refused.
    const stranger = (await h.call("POST", "/v1/apple-mdm/push-csr", { token: admin })).body.csr; // the latest CSR wins
    expect((await h.call("PUT", "/v1/apple-mdm/push-cert", { token: admin, body: { certificate: await appleIssues(csr) } })).body.code).toBe("invalid_certificate");
    const r = await h.call("PUT", "/v1/apple-mdm/push-cert", { token: admin, body: { certificate: await appleIssues(stranger) } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.push.topic).toBe(TOPIC);
    expect((await h.call("GET", "/v1/apple-mdm", { token: admin })).body).toMatchObject({ ready: true, csr_pending: false });
    // A renewal must keep the topic Macs enrolled on.
    const renew = (await h.call("POST", "/v1/apple-mdm/push-csr", { token: admin })).body.csr;
    expect((await h.call("PUT", "/v1/apple-mdm/push-cert", { token: admin, body: { certificate: await appleIssues(renew, "com.apple.mgmt.External.other") } })).body.code).toBe("topic_changed");
    expect((await h.call("PUT", "/v1/apple-mdm/push-cert", { token: admin, body: { certificate: await appleIssues(renew) } })).status).toBe(200);
  });

  it("an enrollment link gives each Mac its own identity and a profile that uses it", async () => {
    const r = await h.call("POST", "/v1/apple-mdm/enrollment-links", { token: admin, body: { name: "Office Macs", expires_in_days: 7 } });
    expect(r.status).toBe(201);
    link = r.body.url;
    expect(link).toMatch(/\/mdm\/apple\/enroll\/nxm_/);
    // The agent is already on this Mac: MDM links to the same device by serial.
    const soft = await new SoftDevice().init();
    const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "t" } })).body.token;
    const body = JSON.stringify({ token: t, device: { hostname: "alice-mba", platform: "macos", os_version: "14.5", serial: "C02TESTSER1", agent_version: "0.2.0" } });
    const agent = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await soft.proof("/v1/agent/enroll", body, { enroll: true })}` }, body });
    const agentId = ((await agent.json()) as { device_id: string }).device_id;

    mac = await enroll(link, "C02TESTSER1");
    expect(mac.mdm).toMatchObject({ Topic: TOPIC, SignMessage: true, CheckInURL: expect.stringContaining("/mdm/apple/checkin"), ServerURL: expect.stringContaining("/mdm/apple/connect") });
    expect(mac.mdm.IdentityCertificateUUID).toBe(mac.payload("com.apple.security.pkcs12").PayloadUUID);
    const list = (await h.call("GET", "/v1/apple-mdm/devices", { token: helpdesk })).body.data;
    expect(list).toEqual([expect.objectContaining({ status: "enrolled", serial: "C02TESTSER1", device_id: agentId, pending_commands: 2 })]);
    const ev = (await db.query("SELECT type FROM audit_events WHERE org_id = $1 AND type LIKE 'apple_mdm.%' ORDER BY id", [orgId])).rows.map((x) => x.type);
    expect(ev).toEqual(expect.arrayContaining(["apple_mdm.profile_downloaded", "apple_mdm.enrolled"]));
    // Tokens are stored sealed, never in the clear.
    const row = (await db.query("SELECT unlock_token FROM apple_mdm_devices WHERE udid = $1", [mac.udid])).rows[0];
    expect(Buffer.from(row.unlock_token).toString()).not.toContain("unlock");
  });

  it("refuses unsigned, forged and foreign messages", async () => {
    expect((await device(mac, "connect", { Status: "Idle" }, { unsigned: true })).status).toBe(401);
    // Signed by a key that isn't the identity's.
    const other = await enroll(link);
    expect((await device(mac, "connect", { Status: "Idle" }, { signAs: { certPem: mac.certPem, keyPem: other.keyPem } })).status).toBe(401);
    // A genuine identity speaking for another Mac's UDID.
    const spoof = Object.assign(Object.create(Object.getPrototypeOf(other)), other, { udid: mac.udid });
    expect((await device(spoof, "connect", { Status: "Idle" })).status).toBe(401);
    expect((await device(mac, "checkin", { MessageType: "Authenticate", Topic: "com.apple.mgmt.External.nope" })).status).toBe(400);
  });

  it("runs the enrollment inventory and records the results", async () => {
    let next = (await idle(mac)).body;
    expect(next.Command.RequestType).toBe("DeviceInformation");
    next = (await ack(mac, next.CommandUUID, { QueryResponses: { DeviceName: "Alice's MacBook Air", OSVersion: "14.6", ModelName: "MacBook Air", SerialNumber: "C02TESTSER1" } })).body;
    expect(next.Command.RequestType).toBe("SecurityInfo");
    expect((await ack(mac, next.CommandUUID, { SecurityInfo: { FDE_Enabled: true, SystemIntegrityProtectionEnabled: true } })).status).toBe(200);
    expect((await idle(mac)).body).toBeNull(); // nothing left
    const d = (await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data.find((x: { serial: string }) => x.serial === "C02TESTSER1");
    expect(d).toMatchObject({ device_name: "Alice's MacBook Air", os_version: "14.6", filevault: true, pending_commands: 0 });
  });

  it("locks a Mac: PIN shown once, device woken by APNs, result audited, PIN not kept", async () => {
    const id = (await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data.find((x: { serial: string }) => x.serial === "C02TESTSER1").id;
    expect((await h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: helpdesk, body: { request_type: "DeviceLock" } })).body.code).toBe("reason_required");
    pushes.length = 0;
    const r = await h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: helpdesk, body: { request_type: "DeviceLock", reason: "Reported stolen", message: "Call IT" } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body).toMatchObject({ pin: expect.stringMatching(/^\d{6}$/), push_error: null });
    expect(pushes).toEqual([{ path: "/3/device/a1b2c3d4", topic: TOPIC, body: JSON.stringify({ mdm: "magic-1" }) }]);
    const cmd = (await idle(mac)).body;
    expect(cmd.Command).toEqual({ RequestType: "DeviceLock", PIN: r.body.pin, Message: "Call IT" });
    await ack(mac, cmd.CommandUUID);
    const row = (await db.query("SELECT status, command FROM apple_mdm_commands WHERE id = $1", [cmd.CommandUUID])).rows[0];
    expect(row.status).toBe("acknowledged");
    expect(JSON.stringify(row.command)).not.toContain(r.body.pin);
    const ev = (await db.query("SELECT type, details FROM audit_events WHERE org_id = $1 AND type IN ('apple_mdm.command_sent', 'apple_mdm.command_finished') ORDER BY id", [orgId])).rows;
    expect(ev.map((e) => [e.type, e.details.request_type])).toEqual([["apple_mdm.command_sent", "DeviceLock"], ["apple_mdm.command_finished", "DeviceLock"]]);
  });

  it("erase needs the wipe permission and the serial typed; NotNow commands come back later", async () => {
    const id = (await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data.find((x: { serial: string }) => x.serial === "C02TESTSER1").id;
    expect((await h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: helpdesk, body: { request_type: "EraseDevice", reason: "Lost" } })).status).toBe(403);
    expect((await h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: admin, body: { request_type: "EraseDevice", reason: "Lost" } })).body.code).toBe("confirm_mismatch");
    await h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: admin, body: { request_type: "RestartDevice", reason: "Apply settings" } });
    await h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: admin, body: { request_type: "InstalledApplicationList" } });
    const first = (await idle(mac)).body;
    expect(first.Command.RequestType).toBe("RestartDevice");
    const second = (await device(mac, "connect", { Status: "NotNow", CommandUUID: first.CommandUUID })).body;
    expect(second.Command.RequestType).toBe("InstalledApplicationList"); // the busy one waits
    const again = (await ack(mac, second.CommandUUID, { InstalledApplicationList: [{ Name: "Safari", Identifier: "com.apple.Safari" }] })).body;
    expect(again.CommandUUID).toBe(first.CommandUUID);
    await ack(mac, first.CommandUUID);
  });

  it("escrows the bootstrap token for its own Mac only, and a removed Mac is unenrolled", async () => {
    await device(mac, "checkin", { MessageType: "SetBootstrapToken", BootstrapToken: Buffer.from("bootstrap-secret") });
    const got = (await device(mac, "checkin", { MessageType: "GetBootstrapToken" })).body;
    expect(Buffer.from(got.BootstrapToken).toString()).toBe("bootstrap-secret");
    expect((await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data.find((x: { serial: string }) => x.serial === "C02TESTSER1").bootstrap_token).toBe(true);

    const id = (await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data.find((x: { serial: string }) => x.serial === "C02TESTSER1").id;
    await h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: admin, body: { request_type: "ProfileList" } });
    expect((await device(mac, "checkin", { MessageType: "CheckOut" })).status).toBe(200);
    expect((await idle(mac)).status).toBe(401);
    expect((await db.query("SELECT count(*)::int AS n FROM apple_mdm_commands WHERE mdm_device_id = $1 AND status = 'queued'", [id])).rows[0].n).toBe(0);
    expect((await h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: admin, body: { request_type: "DeviceInformation" } })).body.code).toBe("not_enrolled");
  });

  it("a revoked link stops working; another organization sees none of it", async () => {
    const links = (await h.call("GET", "/v1/apple-mdm/enrollment-links", { token: admin })).body.data;
    expect(links[0]).toMatchObject({ name: "Office Macs", uses: 2 });
    await h.call("DELETE", `/v1/apple-mdm/enrollment-links/${links[0].id}`, { token: admin });
    expect((await h.app.request(new URL(link).pathname)).status).toBe(404);
    const other = (await h.call("POST", "/v1/signup", { body: { organization_name: "Other Co", email: uniqueEmail("o"), password: PASSWORD, given_name: "O" } })).body.token;
    expect((await h.call("GET", "/v1/apple-mdm/devices", { token: other })).body.data).toEqual([]);
  });
});

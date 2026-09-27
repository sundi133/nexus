import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { webcrypto } from "node:crypto";
import pg from "pg";
import plist from "plist";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build, FakeMac, parse } from "./fake-mac.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** iPhone and iPad in Nexus Apple MDM: platform-aware profiles and commands, next to a Mac. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let apns: http2.Http2Server;
let admin = "";
let mac: FakeMac;
let phone: FakeMac;
let macId = "";
let phoneId = "";
const UNLOCK = Buffer.from("escrowed-unlock-token");
const TOPIC = "com.apple.mgmt.External.11112222-0000-4000-8000-00000000abcd";
const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;

async function device(url: "checkin" | "connect", msg: Record<string, unknown>, d: FakeMac = mac) {
  const body = build({ UDID: d.udid, ...msg });
  const res = await h.app.request(`/mdm/apple/${url}`, { method: "PUT", headers: { "mdm-signature": d.sign(body) }, body });
  const text = await res.text();
  return { status: res.status, body: res.headers.get("content-type")?.includes("xml") ? parse(text) : null };
}
/** Answers everything the Mac is sent until nothing's left; returns what it saw. */
async function drain(d: FakeMac = mac, answer: (cmd: any) => Record<string, unknown> = () => ({ Status: "Acknowledged" })) {
  const seen: any[] = [];
  let next = (await device("connect", { Status: "Idle" }, d)).body;
  while (next) {
    seen.push(next.Command);
    next = (await device("connect", { CommandUUID: next.CommandUUID, ...answer(next.Command) }, d)).body;
  }
  return seen;
}
const send = (id: string, body: Record<string, unknown>) => h.call("POST", `/v1/apple-mdm/devices/${id}/commands`, { token: admin, body: { reason: "Helping", ...body } });
const installs = (seen: any[]) => seen.filter((c) => c.RequestType === "InstallProfile").map((c) => (plist.parse((c.Payload as Buffer).toString("utf8")) as any).PayloadDisplayName).sort();

beforeAll(async () => {
  apns = http2.createServer();
  apns.on("stream", (s: http2.ServerHttp2Stream) => (s.respond({ ":status": 200 }), s.end()));
  await new Promise<void>((r) => apns.listen(0, "127.0.0.1", r));
  h = await bootApp({ appleMdmPushUrl: `http://127.0.0.1:${(apns.address() as AddressInfo).port}` });
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Profiles Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  // Push certificate, as in apple-mdm.e2e.
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=Apple Test CA", notBefore: new Date(Date.now() - 1000), notAfter: new Date(Date.now() + 86_400_000 * 400), signingAlgorithm: ALG, keys });
  const { csr } = (await h.call("POST", "/v1/apple-mdm/push-csr", { token: admin })).body;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: "0a", subject: `0.9.2342.19200300.100.1.1=${TOPIC}, CN=APSP`, issuer: ca.subject, notBefore: new Date(Date.now() - 1000), notAfter: new Date(Date.now() + 365 * 86_400_000), signingAlgorithm: ALG, publicKey: await new x509.Pkcs10CertificateRequest(csr).publicKey.export(), signingKey: keys.privateKey });
  await h.call("PUT", "/v1/apple-mdm/push-cert", { token: admin, body: { certificate: cert.toString("pem") } });
  const link = (await h.call("POST", "/v1/apple-mdm/enrollment-links", { token: admin, body: { name: "Macs" } })).body.url;
  const profileBytes = Buffer.from(await (await h.app.request(new URL(link).pathname)).arrayBuffer());
  mac = new FakeMac(profileBytes);
  phone = new FakeMac(profileBytes, undefined, `F2L${Math.random().toString(36).slice(2, 9).toUpperCase()}`);
  await device("checkin", { MessageType: "Authenticate", Topic: TOPIC, SerialNumber: mac.serial, ProductName: "Mac15,13", Model: "Mac15,13", OSVersion: "14.5" });
  await device("checkin", { MessageType: "TokenUpdate", Topic: TOPIC, Token: Buffer.from("aa", "hex"), PushMagic: "m" });
  // The same profile, installed from Safari on an iPhone (which escrows an unlock token).
  await device("checkin", { MessageType: "Authenticate", Topic: TOPIC, SerialNumber: phone.serial, ProductName: "iPhone15,2", Model: "D73AP", OSVersion: "18.0", DeviceName: "Ana's iPhone" }, phone);
  await device("checkin", { MessageType: "TokenUpdate", Topic: TOPIC, Token: Buffer.from("bb", "hex"), PushMagic: "p", UnlockToken: UNLOCK }, phone);
  await drain();
  await drain(phone, (cmd) => (cmd.RequestType === "SecurityInfo" ? { Status: "Acknowledged", SecurityInfo: { PasscodePresent: true } } : { Status: "Acknowledged" }));
  const list = (await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data;
  macId = list.find((d: any) => d.serial === mac.serial).id;
  phoneId = list.find((d: any) => d.serial === phone.serial).id;
});
afterAll(async () => {
  apns.close();
  await db.end();
  await h.close();
});

describe("iPhone and iPad", () => {
  it("knows an iPhone from a Mac", async () => {
    const list = (await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data;
    expect(list.find((d: any) => d.id === macId)).toMatchObject({ platform: "macos" });
    expect(list.find((d: any) => d.id === phoneId)).toMatchObject({ platform: "ios", device_name: "Ana's iPhone", passcode: true, lost_mode: false, assigned_user: null });
  });

  it("installs each profile only on the devices it's made for", async () => {
    for (const [name, kind, settings] of [["Firewall", "firewall", {}], ["Passcode", "passcode", { min_length: 6 }], ["Office Wi-Fi", "wifi", { ssid: "Acme", password: "correct-horse" }]] as const) {
      expect((await h.call("POST", "/v1/apple-mdm/profiles/template", { token: admin, body: { name, kind, settings } })).status).toBe(201);
    }
    expect(installs(await drain())).toEqual(["Firewall", "Office Wi-Fi", "Passcode"]);
    const onPhone = await drain(phone);
    expect(installs(onPhone)).toEqual(["Office Wi-Fi", "Passcode"]);
    const passcode = onPhone.find((c) => c.RequestType === "InstallProfile" && (plist.parse(c.Payload.toString("utf8")) as any).PayloadDisplayName === "Passcode");
    expect((plist.parse(passcode.Payload.toString("utf8")) as any).PayloadContent[0]).toMatchObject({ PayloadType: "com.apple.mobiledevice.passwordpolicy", forcePIN: true, minLength: 6 });
    const profiles = (await h.call("GET", "/v1/apple-mdm/profiles", { token: admin })).body.data;
    expect(Object.fromEntries(profiles.map((p: any) => [p.name, [p.platforms, p.counts.installed]]))).toEqual({
      Firewall: [["macos"], 1],
      Passcode: [["macos", "ios", "ipados"], 2],
      "Office Wi-Fi": [["macos", "ios", "ipados"], 2],
    });
  });

  it("sends commands that fit the device: no lock PIN on an iPhone, Lost Mode only on phones", async () => {
    expect((await send(macId, { request_type: "DeviceLock" })).body.pin).toMatch(/^\d{6}$/);
    const lock = await send(phoneId, { request_type: "DeviceLock", message: "Call IT", phone: "+1 555 0100" });
    expect(lock.body.pin).toBeNull();
    expect((await send(macId, { request_type: "EnableLostMode" })).body.code).toBe("unsupported");
    expect((await send(phoneId, { request_type: "DeviceLocation" })).body.code).toBe("not_lost");
    await send(phoneId, { request_type: "EnableLostMode", message: "Lost phone", phone: "+1 555 0100" });
    const seen = await drain(phone);
    expect(seen.find((c) => c.RequestType === "DeviceLock")).toEqual({ RequestType: "DeviceLock", Message: "Call IT", PhoneNumber: "+1 555 0100" });
    expect(seen.find((c) => c.RequestType === "EnableLostMode")).toMatchObject({ Message: "Lost phone", PhoneNumber: "+1 555 0100" });
    expect((await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data.find((d: any) => d.id === phoneId).lost_mode).toBe(true);
    expect((await send(phoneId, { request_type: "DeviceLocation" })).status).toBe(201);
    await drain(phone, (cmd) => (cmd.RequestType === "DeviceLocation" ? { Status: "Acknowledged", Latitude: 52.52, Longitude: 13.405 } : { Status: "Acknowledged" }));
    await send(phoneId, { request_type: "DisableLostMode" });
    await drain(phone);
    expect((await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data.find((d: any) => d.id === phoneId).lost_mode).toBe(false);
  });

  it("clears a forgotten passcode with the escrowed unlock token, and doesn't keep it", async () => {
    expect((await send(macId, { request_type: "ClearPasscode" })).body.code).toBe("unsupported");
    const r = await send(phoneId, { request_type: "ClearPasscode" });
    expect(r.status).toBe(201);
    const seen = await drain(phone);
    const clear = seen.find((c) => c.RequestType === "ClearPasscode");
    expect(Buffer.from(clear.UnlockToken).equals(UNLOCK)).toBe(true);
    const stored = (await db.query("SELECT command FROM apple_mdm_commands WHERE id = $1", [r.body.id])).rows[0].command;
    expect(stored).not.toHaveProperty("UnlockToken");
  });

  it("gives a phone an owner, so profiles for their groups reach it", async () => {
    const email = uniqueEmail("ana");
    const ana = (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Ana", password: PASSWORD } })).body.id;
    const group = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "Sales" } })).body.id;
    await h.call("POST", `/v1/groups/${group}/members`, { token: admin, body: { user_ids: [ana] } });
    await h.call("POST", "/v1/apple-mdm/profiles/template", { token: admin, body: { name: "Sales Wi-Fi", kind: "wifi", settings: { ssid: "Sales", password: "sales-pass-1" }, target: { group_ids: [group] } } });
    expect(installs(await drain(phone))).toEqual([]);
    expect((await h.call("PUT", `/v1/apple-mdm/devices/${phoneId}/user`, { token: admin, body: { user_id: ana } })).status).toBe(204);
    expect(installs(await drain(phone))).toEqual(["Sales Wi-Fi"]);
    expect((await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data.find((d: any) => d.id === phoneId).assigned_user).toMatchObject({ email });
  });
});

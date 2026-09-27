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

/** Configuration profiles: built, installed, retargeted and removed on a simulated Mac. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let apns: http2.Http2Server;
let admin = "";
let mac: FakeMac;
let macId = "";
const TOPIC = "com.apple.mgmt.External.11112222-0000-4000-8000-00000000abcd";
const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;

async function device(url: "checkin" | "connect", msg: Record<string, unknown>) {
  const body = build({ UDID: mac.udid, ...msg });
  const res = await h.app.request(`/mdm/apple/${url}`, { method: "PUT", headers: { "mdm-signature": mac.sign(body) }, body });
  const text = await res.text();
  return { status: res.status, body: res.headers.get("content-type")?.includes("xml") ? parse(text) : null };
}
/** Answers everything the Mac is sent until nothing's left; returns what it saw. */
async function drain(answer: (cmd: any) => Record<string, unknown> = () => ({ Status: "Acknowledged" })) {
  const seen: any[] = [];
  let next = (await device("connect", { Status: "Idle" })).body;
  while (next) {
    seen.push(next.Command);
    next = (await device("connect", { CommandUUID: next.CommandUUID, ...answer(next.Command) })).body;
  }
  return seen;
}

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
  mac = new FakeMac(Buffer.from(await (await h.app.request(new URL(link).pathname)).arrayBuffer()));
  await device("checkin", { MessageType: "Authenticate", Topic: TOPIC, SerialNumber: mac.serial, Model: "Mac15,13", OSVersion: "14.5" });
  await device("checkin", { MessageType: "TokenUpdate", Topic: TOPIC, Token: Buffer.from("aa", "hex"), PushMagic: "m" });
  await drain(); // enrollment inventory
  macId = (await h.call("GET", "/v1/apple-mdm/devices", { token: admin })).body.data[0].id;
});
afterAll(async () => {
  apns.close();
  await db.end();
  await h.close();
});

describe("configuration profiles", () => {
  it("builds a profile from a template and installs it on the Mac, payload as real plist data", async () => {
    const r = await h.call("POST", "/v1/apple-mdm/profiles/template", { token: admin, body: { name: "Office Wi-Fi", kind: "wifi", settings: { ssid: "Acme", password: "correct-horse" } } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body).toMatchObject({ source: "template", payload_types: ["com.apple.wifi.managed"], counts: { installing: 1 } });
    // Stored sealed: the Wi-Fi password isn't readable in the database.
    const raw = (await db.query("SELECT payload FROM apple_mdm_profiles WHERE id = $1", [r.body.id])).rows[0].payload as Buffer;
    expect(raw.toString("latin1")).not.toContain("correct-horse");

    const seen = await drain();
    expect(seen.map((c) => c.RequestType)).toEqual(["InstallProfile"]);
    const inner = plist.parse(Buffer.from(seen[0].Payload).toString()) as any;
    expect(inner).toMatchObject({ PayloadType: "Configuration", PayloadIdentifier: r.body.identifier });
    expect(inner.PayloadContent[0]).toMatchObject({ PayloadType: "com.apple.wifi.managed", SSID_STR: "Acme", Password: "correct-horse" });
    expect((await h.call("GET", "/v1/apple-mdm/profiles", { token: admin })).body.data[0].counts).toEqual({ installed: 1, installing: 0, failed: 0 });
    expect(await drain()).toEqual([]); // nothing to redo
  });

  it("retargeting away removes it; a failed install is reported; MDM payloads are refused", async () => {
    const id = (await h.call("GET", "/v1/apple-mdm/profiles", { token: admin })).body.data[0].id;
    const group = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "Design" } })).body.id;
    await h.call("PATCH", `/v1/apple-mdm/profiles/${id}`, { token: admin, body: { target: { group_ids: [group] } } });
    const seen = await drain();
    expect(seen.map((c) => [c.RequestType, c.Identifier])).toEqual([["RemoveProfile", expect.stringContaining("com.votal.nexus.profile.")]]);
    expect((await h.call("GET", `/v1/apple-mdm/devices/${macId}/profiles`, { token: admin })).body.data).toEqual([]);

    await h.call("POST", "/v1/apple-mdm/profiles/template", { token: admin, body: { name: "Lock", kind: "screen_lock", settings: { idle_minutes: 5 } } });
    await drain(() => ({ Status: "Error", ErrorChain: [{ LocalizedDescription: "Profile installation failed" }] }));
    const states = (await h.call("GET", `/v1/apple-mdm/devices/${macId}/profiles`, { token: admin })).body.data;
    expect(states).toEqual([expect.objectContaining({ name: "Lock", status: "failed", detail: "Profile installation failed" })]);

    const evil = plist.build({ PayloadType: "Configuration", PayloadIdentifier: "x.y", PayloadUUID: "1", PayloadVersion: 1, PayloadContent: [{ PayloadType: "com.apple.mdm", ServerURL: "https://evil.example" }] } as plist.PlistValue);
    expect((await h.call("POST", "/v1/apple-mdm/profiles", { token: admin, body: { name: "x", mobileconfig: evil } })).body.code).toBe("mdm_payload");
    expect((await h.call("POST", "/v1/apple-mdm/profiles", { token: admin, body: { name: "x", mobileconfig: "<plist>not a profile</plist>".padEnd(60) } })).body.code).toBe("invalid_profile");
  });
});

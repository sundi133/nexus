import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { createHmac, webcrypto } from "node:crypto";
import http from "node:http";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import forge from "node-forge";
import pg from "pg";
import plist from "plist";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build, FakeMac } from "./fake-mac.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Zero-touch enrollment: server token, device sync, profile assignment, and a Mac in Setup Assistant. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let dep: http.Server;
let apns: http2.Http2Server;
let depBase = "";
let admin = "";
const TOKEN = { consumer_key: "CK_test", consumer_secret: "CS_secret", access_token: "AT_test", access_secret: "AS_secret", access_token_expiry: "2027-09-01T00:00:00Z" };
const TOPIC = "com.apple.mgmt.External.33334444-0000-4000-8000-00000000abcd";
const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;
const abm = { devices: [{ serial_number: "C02ADE00001", model: "MacBook Air", description: "MBA 13\"", color: "space gray", os: "OSX", profile_status: "empty" }, { serial_number: "C02ADE00002", model: "MacBook Pro", os: "OSX", profile_status: "empty" }] as any[], changes: [] as any[], profiles: [] as any[], assigned: [] as any[], sessions: 0 };
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** Independent OAuth 1.0a check, as Apple does it. */
function validOAuth(header: string, url: string) {
  const params = Object.fromEntries([...header.replace(/^OAuth /, "").matchAll(/(\w+)="([^"]*)"/g)].map((m) => [decodeURIComponent(m[1]!), decodeURIComponent(m[2]!)]));
  const { oauth_signature: sig, ...rest } = params;
  if (rest.oauth_consumer_key !== TOKEN.consumer_key || rest.oauth_token !== TOKEN.access_token || rest.oauth_signature_method !== "HMAC-SHA1") return false;
  const base = ["GET", enc(url), enc(Object.keys(rest).sort().map((k) => `${enc(k)}=${enc(rest[k]!)}`).join("&"))].join("&");
  return createHmac("sha1", `${enc(TOKEN.consumer_secret)}&${enc(TOKEN.access_secret)}`).update(base).digest("base64") === sig;
}

async function handle(req: http.IncomingMessage, res: http.ServerResponse) {
  const json = (code: number, b: unknown) => res.writeHead(code, { "content-type": "application/json" }).end(JSON.stringify(b));
  let raw = "";
  for await (const c of req) raw += c;
  const bodyIn = raw ? JSON.parse(raw) : {};
  if (req.url === "/session") {
    if (!validOAuth(req.headers.authorization ?? "", `${depBase}/session`)) return json(401, { error: "bad oauth" });
    abm.sessions++;
    return json(200, { auth_session_token: "SESSION1" });
  }
  if (req.headers["x-adm-auth-session"] !== "SESSION1" || req.headers["x-server-protocol-version"] !== "3") return json(401, {});
  if (req.url === "/account") return json(200, { server_name: "Nexus MDM", org_name: "Acme Inc" });
  if (req.url === "/server/devices") {
    const page = bodyIn.cursor ? abm.devices.slice(1) : abm.devices.slice(0, 1);
    return json(200, { devices: page, cursor: bodyIn.cursor ? "CURSOR2" : "CURSOR1", more_to_follow: !bodyIn.cursor });
  }
  if (req.url === "/devices/sync") return json(200, { devices: abm.changes, cursor: "CURSOR3", more_to_follow: false });
  if (req.url === "/profile" && req.method === "POST") {
    abm.profiles.push(bodyIn);
    return json(200, { profile_uuid: `PROFILE${abm.profiles.length}`, devices: Object.fromEntries((bodyIn.devices ?? []).map((s: string) => [s, "SUCCESS"])) });
  }
  if (req.url === "/profile/devices" && req.method === "PUT") {
    abm.assigned.push(bodyIn);
    return json(200, { profile_uuid: bodyIn.profile_uuid, devices: {} });
  }
  json(404, {});
}

/** What Apple Business Manager does: encrypt the token (in a MIME message) to the uploaded certificate. */
function serverToken(certPem: string) {
  const p7 = forge.pkcs7.createEnvelopedData();
  p7.addRecipient(forge.pki.certificateFromPem(certPem));
  p7.content = forge.util.createBuffer(`Content-Type: text/plain;charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n-----BEGIN MESSAGE-----\n${JSON.stringify(TOKEN)}\n-----END MESSAGE-----\n`);
  p7.encrypt();
  const b64 = forge.util.encode64(forge.asn1.toDer(p7.toAsn1()).getBytes()).match(/.{1,76}/g)!.join("\r\n");
  return `Content-Type: application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="smime.p7m"\r\n\r\n${b64}\r\n`;
}

/** A Mac's machine info, CMS-signed with content attached (as in Setup Assistant). */
function machineInfo(serial: string) {
  const keys = forge.pki.rsa.generateKeyPair(1024);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date(Date.now() + 86_400_000);
  cert.setSubject([{ name: "commonName", value: "Apple Device" }]);
  cert.setIssuer([{ name: "commonName", value: "Apple Device" }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const oids = forge.pki.oids as Record<string, string>;
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(plist.build({ UDID: `UDID-${serial}`, SERIAL: serial, PRODUCT: "Mac15,13", VERSION: "23F79", LANGUAGE: "en" } as plist.PlistValue));
  p7.addCertificate(cert);
  p7.addSigner({ key: keys.privateKey, certificate: cert, digestAlgorithm: oids.sha256!, authenticatedAttributes: [{ type: oids.contentType!, value: oids.data! }, { type: oids.messageDigest! }, { type: oids.signingTime!, value: new Date() as unknown as string }] });
  p7.sign();
  return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), "binary");
}

beforeAll(async () => {
  dep = http.createServer((q, r) => void handle(q, r).catch((e) => r.writeHead(500).end(String(e))));
  await new Promise<void>((r) => dep.listen(0, "127.0.0.1", r));
  depBase = `http://127.0.0.1:${(dep.address() as AddressInfo).port}`;
  apns = http2.createServer();
  apns.on("stream", (s: http2.ServerHttp2Stream) => (s.respond({ ":status": 200 }), s.end()));
  await new Promise<void>((r) => apns.listen(0, "127.0.0.1", r));
  h = await bootApp({ appleDepBase: depBase, appleMdmPushUrl: `http://127.0.0.1:${(apns.address() as AddressInfo).port}` });
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "ADE Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const ca = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=Apple Test CA", notBefore: new Date(Date.now() - 1000), notAfter: new Date(Date.now() + 86_400_000 * 400), signingAlgorithm: ALG, keys });
  const { csr } = (await h.call("POST", "/v1/apple-mdm/push-csr", { token: admin })).body;
  const cert = await x509.X509CertificateGenerator.create({ serialNumber: "0a", subject: `0.9.2342.19200300.100.1.1=${TOPIC}, CN=APSP`, issuer: ca.subject, notBefore: new Date(Date.now() - 1000), notAfter: new Date(Date.now() + 365 * 86_400_000), signingAlgorithm: ALG, publicKey: await new x509.Pkcs10CertificateRequest(csr).publicKey.export(), signingKey: keys.privateKey });
  await h.call("PUT", "/v1/apple-mdm/push-cert", { token: admin, body: { certificate: cert.toString("pem") } });
});
afterAll(async () => {
  dep.close();
  apns.close();
  await db.end();
  await h.close();
});

describe("Apple Business Manager (zero-touch)", () => {
  let enrollUrl = "";

  it("connects with a server token encrypted to Nexus's key, syncs Macs and assigns its profile", async () => {
    const { certificate } = (await h.call("POST", "/v1/apple-mdm/ade/public-key", { token: admin })).body;
    expect(certificate).toContain("BEGIN CERTIFICATE");
    // A token for another key doesn't open.
    const other = forge.pki.rsa.generateKeyPair(1024);
    const oc = forge.pki.createCertificate();
    oc.publicKey = other.publicKey;
    oc.serialNumber = "02";
    oc.validity.notBefore = new Date();
    oc.validity.notAfter = new Date(Date.now() + 86_400_000);
    oc.sign(other.privateKey, forge.md.sha256.create());
    expect((await h.call("PUT", "/v1/apple-mdm/ade/token", { token: admin, body: { token: serverToken(forge.pki.certificateToPem(oc)) } })).body.code).toBe("invalid_token");

    const r = await h.call("PUT", "/v1/apple-mdm/ade/token", { token: admin, body: { token: serverToken(certificate), profile: { profile_name: "Acme Macs", support_email_address: "it@acme.test", is_mdm_removable: false } } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body).toMatchObject({ connected: true, server_name: "Nexus MDM", abm_org_name: "Acme Inc", devices: 2, token_expires_at: "2027-09-01T00:00:00.000Z" });
    enrollUrl = r.body.enroll_url;
    expect(abm.profiles[0]).toMatchObject({ profile_name: "Acme Macs", url: enrollUrl, is_mdm_removable: false, is_mandatory: true, support_email_address: "it@acme.test", devices: ["C02ADE00001", "C02ADE00002"] });
    // The token is kept sealed.
    const raw = (await db.query("SELECT token FROM apple_ade_settings")).rows.map((x) => Buffer.from(x.token).toString("latin1")).join();
    expect(raw).not.toContain("CS_secret");
  });

  it("later syncs pick up added and removed Macs, and new ones get the profile", async () => {
    abm.changes = [{ serial_number: "C02ADE00003", model: "Mac mini", op_type: "added", profile_status: "empty" }, { serial_number: "C02ADE00002", op_type: "deleted" }];
    const r = await h.call("POST", "/v1/apple-mdm/ade/sync", { token: admin });
    expect(r.body).toEqual({ changes: 2, assigned: 1 });
    expect(abm.assigned.at(-1)).toEqual({ profile_uuid: "PROFILE1", devices: ["C02ADE00003"] });
    const list = (await h.call("GET", "/v1/apple-mdm/ade/devices", { token: admin })).body.data.map((d: any) => d.serial);
    expect(list).toEqual(["C02ADE00001", "C02ADE00003"]);
  });

  it("a Mac in Setup Assistant gets its enrollment profile, then enrolls; unknown serials and forged info are refused", async () => {
    const path = new URL(enrollUrl).pathname;
    expect((await h.app.request(path, { method: "POST", body: new Uint8Array(machineInfo("C02NOTOURS1")) })).status).toBe(403);
    const tampered = machineInfo("C02ADE00001");
    tampered[tampered.length - 40] = tampered[tampered.length - 40]! ^ 0xff;
    expect((await h.app.request(path, { method: "POST", body: new Uint8Array(tampered) })).status).toBe(400);
    expect((await h.app.request("/mdm/apple/ade/not-a-secret/enroll", { method: "POST", body: new Uint8Array(machineInfo("C02ADE00001")) })).status).toBe(404);

    const res = await h.app.request(path, { method: "POST", body: new Uint8Array(machineInfo("C02ADE00001")) });
    expect(res.status).toBe(200);
    const mac = new FakeMac(Buffer.from(await res.arrayBuffer()), "UDID-C02ADE00001", "C02ADE00001");
    const sign = (msg: Record<string, unknown>) => {
      const b = build({ UDID: mac.udid, ...msg });
      return h.app.request("/mdm/apple/checkin", { method: "PUT", headers: { "mdm-signature": mac.sign(b) }, body: b });
    };
    expect((await sign({ MessageType: "Authenticate", Topic: TOPIC, SerialNumber: mac.serial, Model: "Mac15,13", OSVersion: "14.5" })).status).toBe(200);
    expect((await sign({ MessageType: "TokenUpdate", Topic: TOPIC, Token: Buffer.from("bb", "hex"), PushMagic: "m" })).status).toBe(200);
    const ade = (await h.call("GET", "/v1/apple-mdm/ade/devices", { token: admin })).body.data.find((d: any) => d.serial === "C02ADE00001");
    expect(ade.enrolled).toBe(true);
    const ev = (await db.query("SELECT actor_display FROM audit_events WHERE type = 'apple_mdm.profile_downloaded' ORDER BY id DESC LIMIT 1")).rows[0];
    expect(ev.actor_display).toBe("Setup Assistant (C02ADE00001)");
  });
});

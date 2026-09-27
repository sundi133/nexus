import { createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, type KeyObject } from "node:crypto";
import { compactVerify, importJWK } from "jose";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** Laptop sign-in with the company account: local accounts in the policy, passwords sealed to the device. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let helpdesk = "";
const eve = { id: "", email: uniqueEmail("eve.smith"), token: "" };
const dev = { d: null as unknown as SoftDevice, id: "", enc: null as unknown as { priv: KeyObject; pub: string } };
let commandKey = "";

const posture = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };
async function checkin(extra: Record<string, unknown> = {}) {
  const body = JSON.stringify({ device: { agent_version: "0.2.0" }, posture, enc_key: dev.enc.pub, ...extra });
  const res = await h.app.request("/v1/agent/checkin", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await dev.d.proof("/v1/agent/checkin", body)}` }, body });
  expect(res.status).toBe(200);
  const out = (await res.json()) as Record<string, any>;
  commandKey = out.command_key;
  return out;
}
const payload = (jws: string) => JSON.parse(Buffer.from(jws.split(".")[1]!, "base64url").toString());

/** What the agent does with an envelope: check the org's signature, then open it with the device key. */
async function open(jws: string) {
  const { payload: raw, protectedHeader } = await compactVerify(jws, await importJWK({ kty: "OKP", crv: "Ed25519", x: commandKey }, "EdDSA"));
  expect(protectedHeader.typ).toBe("nexus-secret+jwt");
  const p = JSON.parse(Buffer.from(raw).toString());
  const b = Buffer.from(p.ct, "base64url");
  const eph = b.subarray(0, 32);
  const shared = diffieHellman({ privateKey: dev.enc.priv, publicKey: createPublicKey({ key: { kty: "OKP", crv: "X25519", x: eph.toString("base64url") }, format: "jwk" }) });
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([eph, Buffer.from(dev.enc.pub, "base64url")]), "nexus-password-v1", 32));
  const d = createDecipheriv("aes-256-gcm", key, b.subarray(32, 44));
  d.setAAD(Buffer.from(`${p.sub}|${p.uid}|${p.ver}`));
  d.setAuthTag(b.subarray(b.length - 16));
  return { ...p, secret: JSON.parse(Buffer.concat([d.update(b.subarray(44, b.length - 16)), d.final()]).toString()) };
}
const login = async (email: string, password: string) => (await h.call("POST", "/v1/auth/login", { body: { email, password } })).body.token as string;

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Laptops Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = await login(hd, PASSWORD);
  eve.id = (await h.call("POST", "/v1/users", { token: admin, body: { email: eve.email, given_name: "Eve", family_name: "Smith", password: PASSWORD } })).body.id;

  const t = (await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: "all" } })).body.token;
  dev.d = await new SoftDevice().init();
  const body = JSON.stringify({ token: t, device: { hostname: "eve-mbp", platform: "macos", os_version: "15.0", agent_version: "0.2.0" } });
  const res = await h.app.request("/v1/agent/enroll", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await dev.d.proof("/v1/agent/enroll", body, { enroll: true })}` }, body });
  dev.d.id = dev.id = ((await res.json()) as any).device_id;
  const kp = generateKeyPairSync("x25519");
  dev.enc = { priv: kp.privateKey, pub: kp.publicKey.export({ format: "jwk" }).x! };
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("local accounts and password sync", () => {
  it("binds a person to a device; only owners and admins grant local admin", async () => {
    await checkin(); // reports the encryption key
    expect((await db.query("SELECT enc_public_key FROM devices WHERE id = $1", [dev.id])).rows[0].enc_public_key).toBe(dev.enc.pub);
    const url = `/v1/devices/${dev.id}/accounts/${eve.id}`;
    expect((await h.call("PUT", url, { token: helpdesk, body: { admin: true } })).status).toBe(403);
    expect((await h.call("PUT", url, { token: helpdesk, body: { username: "root" } })).status).toBe(400);
    const r = await h.call("PUT", url, { token: helpdesk, body: {} });
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ username: eve.email.split("@")[0]!.slice(0, 20).replace(/\.+$/, ""), admin: false, status: "pending", password_synced: false });

    const pol = payload((await checkin()).enforcement);
    expect(pol.accounts).toEqual([{ user_id: eve.id, username: r.body.username, full_name: "Eve Smith", admin: false, state: "active", take_over: false, password_version: 0 }]);
    // Nobody has sent a password yet: none in the check-in.
    expect((await checkin()).passwords).toEqual([]);
  });

  it("sends the password, sealed to the device and signed, when the person signs in", async () => {
    eve.token = await login(eve.email, PASSWORD);
    const env = (await checkin()).passwords as string[];
    expect(env).toHaveLength(1);
    const p = await open(env[0]!);
    expect(p).toMatchObject({ sub: dev.id, uid: eve.id, ver: 1, secret: { password: PASSWORD } });
    // Not stored in the clear anywhere.
    const rows = (await db.query("SELECT ciphertext FROM password_deliveries WHERE user_id = $1", [eve.id])).rows;
    expect(JSON.stringify(rows)).not.toContain(PASSWORD);
    const u = (await db.query("SELECT local_password_fp, password_hash FROM users WHERE id = $1", [eve.id])).rows[0];
    expect(u.local_password_fp).not.toContain(PASSWORD);

    // Until the device says it set it, it's offered again; then it's gone, and the same password isn't re-sent.
    expect(((await checkin()).passwords as string[]).length).toBe(1);
    await checkin({ enforcement: { accounts: [{ user_id: eve.id, username: payload((await checkin()).enforcement).accounts[0].username, status: "active", password_version: 1 }] } });
    expect((await checkin()).passwords).toEqual([]);
    await login(eve.email, PASSWORD);
    expect((await checkin()).passwords).toEqual([]);
    const mine = (await h.call("GET", "/v1/me/device-accounts", { token: eve.token })).body.data;
    expect(mine).toEqual([expect.objectContaining({ hostname: "eve-mbp", status: "active", password_synced: true })]);
    const ev = (await db.query("SELECT type FROM audit_events WHERE target_id = $1 AND type LIKE 'device.local_%' ORDER BY id", [dev.id])).rows.map((r) => r.type);
    expect(ev).toEqual(["device.local_account_bound", "device.local_password_synced"]);
  });

  it("a password change sends the new one with the old (so macOS keeps the keychain and FileVault)", async () => {
    const r = await h.call("PUT", "/v1/me/password", { token: eve.token, body: { current_password: PASSWORD, new_password: `${PASSWORD}-new!` } });
    expect(r.status).toBe(204);
    const p = await open(((await checkin()).passwords as string[])[0]!);
    expect(p).toMatchObject({ ver: 2, secret: { password: `${PASSWORD}-new!`, old: PASSWORD } });
    expect(payload((await checkin()).enforcement).accounts[0].password_version).toBe(2);
  });

  it("a sign-in with a password changed elsewhere (a directory) is sent; a key change drops what can't be opened", async () => {
    // Simulate the directory having changed it: the fingerprint no longer matches.
    await db.query("UPDATE users SET local_password_fp = 'stale' WHERE id = $1", [eve.id]);
    await login(eve.email, `${PASSWORD}-new!`);
    expect((await open(((await checkin()).passwords as string[])[0]!)).ver).toBe(3);
    // The agent was reinstalled with a new key: envelopes for the old one are dropped.
    const kp = generateKeyPairSync("x25519");
    dev.enc = { priv: kp.privateKey, pub: kp.publicKey.export({ format: "jwk" }).x! };
    await checkin();
    expect((await db.query("SELECT count(*)::int AS n FROM password_deliveries WHERE device_id = $1", [dev.id])).rows[0].n).toBe(0);
    await db.query("UPDATE users SET local_password_fp = 'stale' WHERE id = $1", [eve.id]);
    await login(eve.email, `${PASSWORD}-new!`);
    expect((await open(((await checkin()).passwords as string[])[0]!)).ver).toBe(4); // opens with the new key
  });

  it("a suspended person's account is disabled, gets no passwords and loses admin", async () => {
    await h.call("PUT", `/v1/devices/${dev.id}/accounts/${eve.id}`, { token: admin, body: { admin: true } });
    expect(payload((await checkin()).enforcement).accounts[0]).toMatchObject({ admin: true, state: "active" });
    await h.call("POST", `/v1/users/${eve.id}/suspend`, { token: admin, body: { reason: "left" } });
    const out = await checkin();
    expect(payload(out.enforcement).accounts[0]).toMatchObject({ admin: false, state: "disabled" });
    expect(out.passwords).toEqual([]);
  });

  it("an account name is one person's per device, and unbinding needs the right to have bound it", async () => {
    const bob = (await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("bob"), given_name: "Bob" } })).body.id;
    const taken = payload((await checkin()).enforcement).accounts[0].username;
    expect((await h.call("PUT", `/v1/devices/${dev.id}/accounts/${bob}`, { token: admin, body: { username: taken } })).body.code).toBe("username_taken");
    // Eve is a local admin: helpdesk can't remove her; an admin can.
    expect((await h.call("DELETE", `/v1/devices/${dev.id}/accounts/${eve.id}`, { token: helpdesk })).status).toBe(403);
    expect((await h.call("DELETE", `/v1/devices/${dev.id}/accounts/${eve.id}`, { token: admin })).status).toBe(204);
    expect(payload((await checkin()).enforcement).accounts ?? []).toEqual([]);
  });
});

import { createHash, randomBytes } from "node:crypto";
import dgram from "node:dgram";
import { Attribute, Change, Client, InvalidCredentialsError } from "ldapts";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startLdapServer } from "../src/protocols/ldap.js";
import { ATTR, CODE, decode, encode, hidePassword, messageAuthenticator, startRadiusServer } from "../src/protocols/radius.js";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";

/** Nexus as an LDAP directory (a real LDAP client, ldapts) and a RADIUS server. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let slug = "";
let orgId = "";
const pat = { id: "", email: uniqueEmail("pat") };
const kim = { id: "", email: uniqueEmail("kim") };
let ldap: Awaited<ReturnType<typeof startLdapServer>>;
let radius: Awaited<ReturnType<typeof startRadiusServer>>;
let service = { dn: "", password: "" };

const ldapClient = () => new Client({ url: `ldap://127.0.0.1:${ldap.port}`, timeout: 5000 });
const base = () => `o=${slug},dc=nexus`;

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  // RADIUS clients are matched by address across organizations: clear earlier runs' 127.0.0.1.
  await db.query("UPDATE radius_clients SET revoked_at = now() WHERE address = '127.0.0.1/32' AND revoked_at IS NULL");
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Legacy Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token: admin })).body;
  slug = me.organization.slug;
  orgId = me.organization.id;
  for (const [p, name] of [[pat, "Pat"], [kim, "Kim"]] as const) {
    p.id = (await h.call("POST", "/v1/users", { token: admin, body: { email: p.email, given_name: name, family_name: "Lee", title: "Engineer", password: PASSWORD } })).body.id;
  }
  const g = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "VPN Users" } })).body.id;
  await h.call("POST", `/v1/groups/${g}/members`, { token: admin, body: { user_ids: [pat.id] } });
  ldap = await startLdapServer(h.deps, { port: 0, host: "127.0.0.1" });
  radius = await startRadiusServer(h.deps, { port: 0, host: "127.0.0.1" });
});
afterAll(async () => {
  await db.query("UPDATE radius_clients SET revoked_at = now() WHERE org_id = $1", [orgId]);
  await ldap.close();
  await radius.close();
  await db.end();
  await h.close();
});

describe("LDAP", () => {
  it("answers the root entry to anyone, and nothing else before a bind", async () => {
    const c = ldapClient();
    const root = await c.search("", { scope: "base", filter: "(objectClass=*)", attributes: ["namingContexts", "supportedLDAPVersion"] });
    expect(root.searchEntries[0]).toMatchObject({ supportedLDAPVersion: "3" });
    await expect(c.search(base(), { scope: "sub", filter: "(objectClass=*)" })).rejects.toThrow();
    await c.unbind();
  });

  it("refuses binds until the organization turns LDAP on", async () => {
    const acct = await h.call("POST", "/v1/directory-services/ldap/service-accounts", { token: admin, body: { name: "jenkins" } });
    expect(acct.status).toBe(201);
    service = { dn: acct.body.dn, password: acct.body.password };
    const c = ldapClient();
    await expect(c.bind(service.dn, service.password)).rejects.toBeInstanceOf(InvalidCredentialsError);
    await c.unbind();
    expect((await h.call("PUT", "/v1/directory-services", { token: admin, body: { ldap_enabled: true, radius_enabled: true, radius_mfa: "if_enrolled" } })).status).toBe(200);
  });

  it("lets a service account search people and groups, with filters an app would use", async () => {
    const c = ldapClient();
    await c.bind(service.dn, service.password);
    const people = await c.search(`ou=users,${base()}`, { scope: "one", filter: "(objectClass=inetOrgPerson)", attributes: ["uid", "mail", "cn", "sn", "memberOf"] });
    const byMail = new Map(people.searchEntries.map((e) => [e.mail, e]));
    expect(byMail.get(pat.email)).toMatchObject({ uid: pat.email.toLowerCase(), cn: "Pat Lee", sn: "Lee", memberOf: `cn=VPN Users,ou=groups,${base()}` });
    const one = await c.search(base(), { scope: "sub", filter: `(&(objectClass=person)(mail=${pat.email.toUpperCase()}))` });
    expect(one.searchEntries.map((e) => e.dn)).toEqual([`uid=${pat.email.toLowerCase()},ou=users,${base()}`]);
    const sub = await c.search(base(), { scope: "sub", filter: "(&(objectClass=inetOrgPerson)(|(cn=Pa*)(cn=*zz*)))", attributes: ["cn"] });
    expect(sub.searchEntries.map((e) => e.cn)).toEqual(["Pat Lee"]);
    const groups = await c.search(`ou=groups,${base()}`, { scope: "one", filter: `(member=uid=${pat.email.toLowerCase()},ou=users,${base()})`, attributes: ["cn"] });
    expect(groups.searchEntries.map((e) => e.cn)).toEqual(["VPN Users"]);
    // Read-only: changes are made in Nexus.
    await expect(c.modify(`uid=${pat.email.toLowerCase()},ou=users,${base()}`, [new Change({ operation: "replace", modification: new Attribute({ type: "title", values: ["CEO"] }) })])).rejects.toThrow(/read-only/);
    await c.unbind();
  });

  it("checks a person's Nexus password, and shows them only their own entry and groups", async () => {
    const c = ldapClient();
    const dn = `uid=${pat.email},ou=users,${base()}`;
    await expect(c.bind(dn, "wrong-password")).rejects.toBeInstanceOf(InvalidCredentialsError);
    await c.bind(dn, PASSWORD);
    const seen = await c.search(base(), { scope: "sub", filter: "(objectClass=*)", attributes: ["dn"] });
    expect(seen.searchEntries.map((e) => e.dn).sort()).toEqual([`cn=VPN Users,ou=groups,${base()}`, `uid=${pat.email.toLowerCase()},ou=users,${base()}`].sort());
    await c.unbind();
    // Suspended people can't bind, and disappear from the directory.
    await h.call("POST", `/v1/users/${kim.id}/suspend`, { token: admin, body: { reason: "leave" } });
    const k = ldapClient();
    await expect(k.bind(`uid=${kim.email},ou=users,${base()}`, PASSWORD)).rejects.toBeInstanceOf(InvalidCredentialsError);
    await k.unbind();
    const s = ldapClient();
    await s.bind(service.dn, service.password);
    const all = await s.search(`ou=users,${base()}`, { scope: "one", filter: "(objectClass=person)", attributes: ["mail"] });
    expect(all.searchEntries.map((e) => e.mail)).not.toContain(kim.email);
    await s.unbind();
    const binds = (await db.query("SELECT outcome FROM audit_events WHERE org_id = $1 AND type = 'ldap.bind' ORDER BY ts", [orgId])).rows.map((r) => r.outcome);
    expect(binds).toEqual(expect.arrayContaining(["failure", "success"]));
  });
});

// ---- RADIUS: a client like a VPN concentrator ------------------------------------------------------

let secret = "";
type Reply = { code: number; attrs: { type: number; value: Buffer }[]; raw: Buffer };
function send(attrs: { type: number; value: Buffer }[], opts: { id?: number; auth?: Buffer; withMa?: boolean; secretOverride?: string } = {}): Promise<Reply | null> {
  const s = Buffer.from(opts.secretOverride ?? secret);
  const auth = opts.auth ?? randomBytes(16);
  const all = opts.withMa === false ? attrs : [...attrs, { type: ATTR.MessageAuthenticator, value: Buffer.alloc(16) }];
  const pkt = encode({ code: CODE.AccessRequest, id: opts.id ?? 7, authenticator: auth, attrs: all });
  if (opts.withMa !== false) messageAuthenticator(pkt, s, auth).copy(pkt, pkt.length - 16);
  return new Promise((resolve) => {
    const sock = dgram.createSocket("udp4");
    const timer = setTimeout(() => (sock.close(), resolve(null)), 1500);
    sock.on("message", (m) => {
      clearTimeout(timer);
      sock.close();
      const d = decode(m)!;
      // The Response Authenticator, computed independently: MD5(code+id+length+request auth+attributes+secret).
      const expected = createHash("md5").update(Buffer.concat([m.subarray(0, 4), auth, m.subarray(20), s])).digest();
      expect(m.subarray(4, 20)).toEqual(expected);
      expect(d.attrs[0]!.type).toBe(ATTR.MessageAuthenticator); // first, per Blast-RADIUS guidance
      resolve({ code: d.code, attrs: d.attrs, raw: m });
    });
    sock.send(pkt, radius.port, "127.0.0.1");
  });
}
const pap = (user: string, password: string, auth = randomBytes(16)) => ({ auth, attrs: [{ type: ATTR.UserName, value: Buffer.from(user) }, { type: ATTR.UserPassword, value: hidePassword(password, Buffer.from(secret), auth) }] });
const reply = (r: Reply | null, type: number) => r?.attrs.filter((a) => a.type === type).map((a) => a.value.toString());

describe("RADIUS", () => {
  it("ignores requests from addresses that aren't registered", async () => {
    secret = "not-registered";
    const p = pap(pat.email, PASSWORD);
    expect(await send(p.attrs, { auth: p.auth })).toBeNull();
  });

  it("registers a client by address, one per address across organizations", async () => {
    const r = await h.call("POST", "/v1/directory-services/radius/clients", { token: admin, body: { name: "Office VPN", address: "127.0.0.1" } });
    expect(r.status).toBe(201);
    secret = r.body.secret;
    expect((await h.call("POST", "/v1/directory-services/radius/clients", { token: admin, body: { name: "Dup", address: "127.0.0.0/24" } })).body.code).toBe("address_taken");
    expect((await h.call("POST", "/v1/directory-services/radius/clients", { token: admin, body: { name: "Everyone", address: "0.0.0.0/0" } })).body.code).toBe("invalid_address");
  });

  it("drops requests without a valid Message-Authenticator (Blast-RADIUS)", async () => {
    const p = pap(pat.email, PASSWORD);
    expect(await send(p.attrs, { auth: p.auth, withMa: false })).toBeNull();
    expect(await send(p.attrs, { auth: p.auth, secretOverride: "wrong-secret" })).toBeNull();
  });

  it("accepts the right password with the person's groups, and rejects a wrong one", async () => {
    const ok = pap(pat.email, PASSWORD);
    const r = await send(ok.attrs, { auth: ok.auth });
    expect(r?.code).toBe(CODE.AccessAccept);
    expect(reply(r, ATTR.Class)).toEqual(["group:VPN Users"]);
    const bad = pap(pat.email, "nope-nope-nope");
    expect((await send(bad.attrs, { auth: bad.auth }))?.code).toBe(CODE.AccessReject);
  });

  it("answers a retransmission with the same packet", async () => {
    const p = pap(pat.email, PASSWORD);
    const a = await send(p.attrs, { auth: p.auth, id: 42 });
    const b = await send(p.attrs, { auth: p.auth, id: 42 });
    expect(b?.raw).toEqual(a?.raw);
  });

  it("asks people with an authenticator app for a code, and lets them in with it", async () => {
    const token = (await h.call("POST", "/v1/auth/login", { body: { email: pat.email, password: PASSWORD } })).body.token;
    const f = await h.call("POST", "/v1/me/factors/totp", { token, body: {} });
    await h.call("POST", `/v1/me/factors/${f.body.id}/verify`, { token, body: { code: totpCode(f.body.secret) } });

    const p = pap(pat.email, PASSWORD);
    const challenge = await send(p.attrs, { auth: p.auth });
    expect(challenge?.code).toBe(CODE.AccessChallenge);
    expect(reply(challenge, ATTR.ReplyMessage)?.[0]).toContain("authenticator app");
    const state = challenge!.attrs.find((a) => a.type === ATTR.State)!.value;

    const wrong = pap(pat.email, "000000");
    const again = await send([...wrong.attrs, { type: ATTR.State, value: state }], { auth: wrong.auth });
    expect(again?.code).toBe(CODE.AccessChallenge); // a wrong code: try again

    const code = pap(pat.email, totpCode(f.body.secret, 1));
    const done = await send([...code.attrs, { type: ATTR.State, value: state }], { auth: code.auth });
    expect(done?.code).toBe(CODE.AccessAccept);
    const events = (await db.query("SELECT details->>'reason' AS reason, outcome FROM audit_events WHERE org_id = $1 AND type = 'radius.auth' ORDER BY ts", [orgId])).rows;
    expect(events).toEqual(expect.arrayContaining([{ reason: "password+totp", outcome: "success" }, { reason: "bad_password", outcome: "failure" }]));
  });

  it("refuses people without an authenticator app when the organization requires one", async () => {
    await h.call("PUT", "/v1/directory-services", { token: admin, body: { ldap_enabled: true, radius_enabled: true, radius_mfa: "required" } });
    const u = uniqueEmail("nomfa");
    await h.call("POST", "/v1/users", { token: admin, body: { email: u, given_name: "No", password: PASSWORD } });
    const p = pap(u, PASSWORD);
    const r = await send(p.attrs, { auth: p.auth });
    expect(r?.code).toBe(CODE.AccessReject);
    expect(reply(r, ATTR.ReplyMessage)?.[0]).toContain("authenticator app");
  });
});

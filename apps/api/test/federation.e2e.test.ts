import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js"; // first: the app graph loads the reflect polyfill the SAML certificate code needs
import { createHash, randomBytes, randomUUID } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT, type JWTPayload } from "jose";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildResponse, decodeAuthnRequest, idpMetadata } from "../src/sso/saml.js";
import { createSamlCert } from "../src/sso/saml-cert.js";
import { verifySamlResponse } from "../src/federation/saml-sp.js";

/**
 * Signing in through the organization's own IdP (AUTH-10), OIDC and SAML:
 * home-realm discovery, JIT accounts, linking, MFA trust, enforcement, test
 * sign-ins, and the attacks a relying party must refuse.
 */

const RUN = randomUUID().slice(0, 8);
const OIDC_DOMAIN = `acme-${RUN}.test`;
const SAML_DOMAIN = `acme-eu-${RUN}.test`;
const dns = new Map<string, string[]>();
const resolveTxt = async (name: string) => {
  const v = dns.get(name);
  if (!v) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  return v.map((x) => [x]);
};

// ---- A fake OIDC provider (Okta-like): discovery, JWKS, token endpoint with PKCE -------------
let server: http.Server;
let base = "";
let issuer = "";
const CLIENT = { id: "nexus-client", secret: "s3cret:with/odd chars" };
const signing = await generateKeyPair("ES256");
const codes = new Map<string, { challenge: string; redirectUri: string; claims: JWTPayload }>();
let tokenCalls = 0;

// ---- A SAML IdP: signs with its own certificate (made by Nexus's generator, in a throwaway organization) ----
async function samlCert() {
  const t = (await h.call("POST", "/v1/signup", { body: { organization_name: "Fake ADFS", email: uniqueEmail("adfs"), password: PASSWORD, given_name: "A" } })).body.token;
  const org = (await h.call("GET", "/v1/me", { token: t })).body.organization.id;
  const c = await h.deps.db.tenant(org, (tx) => createSamlCert(tx, h.deps, org, "next"));
  return { certPem: c.certPem, privateKeyPem: c.privateKeyPem };
}
const SAML_IDP = "https://adfs.acme-eu.test/adfs/services/trust";
let samlKey: Awaited<ReturnType<typeof samlCert>>;

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";
let sp: { oidc_redirect_uri: string; saml_acs_url: string; saml_entity_id: string; saml_metadata_url: string };
let oidcIdp = "";
let samlIdp = "";

const idps = async () => (await h.call("GET", "/v1/identity-providers", { token: admin })).body;
const me = async (token: string) => (await h.call("GET", "/v1/me", { token })).body;

/** What the browser does: start, "sign in" at the IdP, come back with a code. */
async function oidcLogin(email: string, claims: JWTPayload = {}, opts: { tamper?: (c: JWTPayload) => void } = {}) {
  const start = await h.call("POST", "/v1/auth/federation/start", { body: { email, return_to: "/apps" } });
  expect(start.status, JSON.stringify(start.body)).toBe(200);
  const u = new URL(start.body.redirect_url);
  const code = randomBytes(12).toString("hex");
  const c: JWTPayload = { sub: `okta|${email}`, email, email_verified: true, given_name: "Ada", family_name: "Lovelace", nonce: u.searchParams.get("nonce")!, amr: ["pwd", "mfa"], ...claims };
  opts.tamper?.(c);
  codes.set(code, { challenge: u.searchParams.get("code_challenge")!, redirectUri: u.searchParams.get("redirect_uri")!, claims: c });
  return { state: start.body.state as string, url: u, complete: () => h.call("POST", "/v1/auth/federation/complete", { body: { state: start.body.state, code } }) };
}

/** A signed SAML response to a real AuthnRequest, optionally changed on the way. */
async function samlLogin(email: string, mutate?: (xml: string) => string, o: { audience?: string; key?: typeof samlKey; inResponseTo?: string } = {}) {
  const start = await h.call("POST", "/v1/auth/federation/start", { body: { email } });
  expect(start.status, JSON.stringify(start.body)).toBe(200);
  const u = new URL(start.body.redirect_url);
  expect(u.searchParams.get("RelayState")).toBe(start.body.state);
  const req = decodeAuthnRequest(u.searchParams.get("SAMLRequest")!, "redirect");
  expect(req).toMatchObject({ issuer: sp.saml_entity_id, acsUrl: sp.saml_acs_url });
  let b64 = buildResponse({
    idp: SAML_IDP,
    cfg: { entity_id: o.audience ?? sp.saml_entity_id, acs_url: sp.saml_acs_url, name_id_format: "email", sign: "assertion" },
    user: { id: "u1", email, given_name: "Grace", family_name: "Hopper", department: "", title: "" } as never,
    groups: ["Engineering"],
    inResponseTo: o.inResponseTo ?? req.id,
    sessionIndex: "s1",
    authnInstant: new Date(),
    cert: o.key ?? samlKey,
  });
  if (mutate) b64 = Buffer.from(mutate(Buffer.from(b64, "base64").toString("utf8"))).toString("base64");
  return h.call("POST", "/v1/auth/federation/complete", { body: { state: start.body.state, saml_response: b64 } });
}

async function verifyDomain(domain: string) {
  const r = await h.call("POST", "/v1/org/domains", { token: admin, body: { domain } });
  const d = (r.body.data as Record<string, any>[]).find((x) => x.domain === domain)!;
  dns.set(d.record.name, [d.record.value]);
  const v = await h.call("POST", `/v1/org/domains/${d.id}/verify`, { token: admin, body: {} });
  expect((v.body.data as Record<string, any>[]).find((x) => x.domain === domain)!.status).toBe("verified");
}

beforeAll(async () => {
  const jwk = { ...(await exportJWK(signing.publicKey)), kid: "k1", alg: "ES256", use: "sig" };
  server = http.createServer((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c)).on("end", async () => {
      const json = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
      const path = req.url!.split("?")[0];
      if (path === "/oidc/.well-known/openid-configuration") return json(200, { issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` });
      if (path === "/liar/.well-known/openid-configuration") return json(200, { issuer: "https://evil.example.com", authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks` });
      if (path === "/oidc/jwks") return json(200, { keys: [jwk] });
      if (path === "/oidc/token") {
        tokenCalls++;
        const form = new URLSearchParams(data);
        const [id, secret] = Buffer.from(String(req.headers.authorization).replace(/^Basic /, ""), "base64").toString().split(":").map(decodeURIComponent);
        if (id !== CLIENT.id || secret !== CLIENT.secret) return json(401, { error: "invalid_client" });
        const c = codes.get(form.get("code") ?? "");
        codes.delete(form.get("code") ?? "");
        if (!c) return json(400, { error: "invalid_grant", error_description: "code expired" });
        if (createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url") !== c.challenge) return json(400, { error: "invalid_grant", error_description: "PKCE verification failed" });
        if (form.get("redirect_uri") !== c.redirectUri) return json(400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
        const idToken = await new SignJWT({ ...c.claims })
          .setProtectedHeader({ alg: "ES256", kid: "k1" })
          .setIssuer((c.claims.iss as string) ?? issuer)
          .setAudience((c.claims.aud as string) ?? CLIENT.id)
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(signing.privateKey);
        return json(200, { access_token: "at", token_type: "Bearer", id_token: idToken });
      }
      res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  issuer = `${base}/oidc`;

  h = await bootApp({}, { resolveTxt });
  samlKey = await samlCert();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Acme Fed", email: `root@${OIDC_DOMAIN}`, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await me(admin)).organization.id;
});
afterAll(async () => {
  server.close();
  await owner.end();
  await h.close();
});

describe("connecting an IdP", () => {
  it("needs verified domains, and a truthful discovery document", async () => {
    const oidc = { name: "Okta", protocol: "oidc", issuer, client_id: CLIENT.id, client_secret: CLIENT.secret, domains: [OIDC_DOMAIN] };
    expect((await h.call("POST", "/v1/identity-providers", { token: admin, body: oidc })).body.code).toBe("domain_not_verified");
    await verifyDomain(OIDC_DOMAIN);
    await verifyDomain(SAML_DOMAIN);
    const liar = await h.call("POST", "/v1/identity-providers", { token: admin, body: { ...oidc, issuer: `${base}/liar` } });
    expect(liar.body).toMatchObject({ code: "idp_misconfigured", title: expect.stringContaining("evil.example.com") });

    const r = await h.call("POST", "/v1/identity-providers", { token: admin, body: oidc });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    oidcIdp = r.body.data[0].id;
    sp = r.body.service_provider;
    expect(sp.oidc_redirect_uri).toMatch(/\/federation\/oidc\/callback$/);
    expect(r.body.data[0]).toMatchObject({ protocol: "oidc", issuer, client_id: CLIENT.id, domains: [OIDC_DOMAIN], mfa: "when_signalled", required: false });
    expect(JSON.stringify(r.body)).not.toContain(CLIENT.secret);
    // One IdP per domain.
    expect((await h.call("POST", "/v1/identity-providers", { token: admin, body: { ...oidc, name: "Okta 2" } })).body.code).toBe("domain_in_use");
  });

  it("imports SAML metadata, and publishes ours", async () => {
    const meta = idpMetadata(SAML_IDP, "https://adfs.acme-eu.test/adfs/ls", [samlKey.certPem]);
    const r = await h.call("POST", "/v1/identity-providers", { token: admin, body: { name: "ADFS", protocol: "saml", metadata_xml: meta, domains: [SAML_DOMAIN], jit_provisioning: false } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const idp = (r.body.data as Record<string, any>[]).find((x) => x.name === "ADFS")!;
    samlIdp = idp.id;
    expect(idp).toMatchObject({ idp_entity_id: SAML_IDP, idp_sso_url: "https://adfs.acme-eu.test/adfs/ls", certificates: [{ subject: expect.stringContaining("Fake ADFS") }] });
    const slug = (await me(admin)).organization.slug;
    const md = await h.app.request(`/v1/federation/saml/${slug}/metadata`);
    const xml = await md.text();
    expect(md.headers.get("content-type")).toContain("samlmetadata+xml");
    expect(xml).toContain(`entityID="${sp.saml_entity_id}"`);
    expect(xml).toContain(`Location="${sp.saml_acs_url}"`);
  });

  it("tells the sign-in page who signs in where, without revealing accounts", async () => {
    const d = (email: string) => h.call("POST", "/v1/auth/federation/discover", { body: { email } });
    expect((await d(`nobody@${OIDC_DOMAIN}`)).body).toEqual({ federated: true, provider: { name: "Okta" }, required: false });
    expect((await d(`x@${SAML_DOMAIN}`)).body.provider.name).toBe("ADFS");
    expect((await d("someone@gmail.com")).body).toEqual({ federated: false, provider: null, required: false });
  });
});

describe("signing in with OIDC", () => {
  const ada = `ada@${OIDC_DOMAIN}`;

  it("creates the account on first sign-in, and trusts the IdP's MFA when it says so", async () => {
    const login = await oidcLogin(ada);
    expect(Object.fromEntries(login.url.searchParams)).toMatchObject({ response_type: "code", client_id: CLIENT.id, code_challenge_method: "S256", login_hint: ada, state: login.state });
    const r = await login.complete();
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body).toMatchObject({ purpose: "login", session: { state: "active" }, return_to: "/apps" });
    const m = await me(r.body.token);
    expect(m.user).toMatchObject({ email: ada, given_name: "Ada", family_name: "Lovelace", status: "active" });
    expect(m.session.mfa_at).not.toBeNull(); // MFA done at the IdP
    const ev = (await h.call("GET", "/v1/audit/events?type=auth.login", { token: admin })).body.data[0];
    expect(ev).toMatchObject({ outcome: "success", actor: { display: ada }, details: { method: "federation", idp: "Okta", mfa: "idp" } });
    expect((await idps()).data.find((x: any) => x.id === oidcIdp).linked_users).toBe(1);
  });

  it("is single-use: the same answer can't be replayed", async () => {
    const login = await oidcLogin(ada);
    expect((await login.complete()).status).toBe(200);
    const again = await h.call("POST", "/v1/auth/federation/complete", { body: { state: login.state, code: "anything" } });
    expect(again).toMatchObject({ status: 401, body: { code: "expired_request" } });
  });

  it("applies Nexus MFA when the IdP didn't do MFA", async () => {
    const r = await (await oidcLogin(ada, { amr: ["pwd"] })).complete();
    expect(r.body.session.state).toBe("active"); // no factors and no org requirement
    const s = await me(r.body.token);
    expect(s.session.mfa_at).toBeNull();
    // With a TOTP factor, the session waits for it.
    const f = await h.call("POST", "/v1/me/factors/totp", { token: r.body.token, body: {} });
    await h.call("POST", `/v1/me/factors/${f.body.id}/verify`, { token: r.body.token, body: { code: totpCode(f.body.secret) } });
    const again = await (await oidcLogin(ada, { amr: ["pwd"] })).complete();
    expect(again.body).toMatchObject({ session: { state: "pending_mfa" }, mfa: { required: true, factors: ["totp"] } });
  });

  it("refuses tokens that aren't for this sign-in", async () => {
    const nonce = await (await oidcLogin(`eve@${OIDC_DOMAIN}`, {}, { tamper: (c) => void (c.nonce = "other") })).complete();
    expect(nonce.body).toMatchObject({ status: 401, code: "invalid_token" });
    const aud = await (await oidcLogin(`eve@${OIDC_DOMAIN}`, { aud: "another-app" })).complete();
    expect(aud.body.code).toBe("invalid_token");
    const iss = await (await oidcLogin(`eve@${OIDC_DOMAIN}`, { iss: "https://evil.example.com" })).complete();
    expect(iss.body.code).toBe("invalid_token");
    const unverified = await (await oidcLogin(`eve@${OIDC_DOMAIN}`, { email_verified: false })).complete();
    expect(unverified.body.code).toBe("email_unverified");
    // The IdP can only vouch for its own domains.
    const other = await (await oidcLogin(`eve@${OIDC_DOMAIN}`, { email: "ceo@othercorp.com" })).complete();
    expect(other.body).toMatchObject({ code: "domain_not_allowed" });
    const fails = (await h.call("GET", "/v1/audit/events?type=auth.login&outcome=failure", { token: admin })).body.data;
    expect(fails.map((e: any) => e.details.reason)).toEqual(expect.arrayContaining(["invalid_token", "email_unverified", "domain_not_allowed"]));
  });

  it("activates invited people, links by email, and keeps suspended people out", async () => {
    const grace = `grace@${OIDC_DOMAIN}`;
    const invited = (await h.call("POST", "/v1/users", { token: admin, body: { email: grace, given_name: "Grace", invite: true } })).body;
    const r = await (await oidcLogin(grace, { sub: "okta|grace-subject" })).complete();
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const m = await me(r.body.token);
    expect(m.user).toMatchObject({ id: invited.id, status: "active" });
    // The link is by subject from now on: a changed email at the IdP still reaches the same account.
    await h.call("POST", `/v1/users/${invited.id}/suspend`, { token: admin, body: {} });
    const refused = await (await oidcLogin(grace, { sub: "okta|grace-subject" })).complete();
    expect(refused.body).toMatchObject({ status: 401, code: "account_inactive" });
  });

  it("never moves a link to a different IdP identity presenting the same email", async () => {
    const ivy = `ivy@${OIDC_DOMAIN}`;
    await h.call("POST", "/v1/users", { token: admin, body: { email: ivy, given_name: "Ivy", password: PASSWORD } });
    expect((await (await oidcLogin(ivy, { sub: "okta|ivy-real" })).complete()).status).toBe(200);
    const hijack = await (await oidcLogin(ivy, { sub: "okta|someone-else" })).complete();
    expect(hijack.body.code).toBe("identity_mismatch");
    expect((await (await oidcLogin(ivy, { sub: "okta|ivy-real" })).complete()).status).toBe(200); // the real one still works
  });

  it("keeps break-glass accounts off the IdP", async () => {
    const bg = `emergency@${OIDC_DOMAIN}`;
    const id = (await h.call("POST", "/v1/users", { token: admin, body: { email: bg, given_name: "Break", password: PASSWORD } })).body.id;
    await owner.query("UPDATE users SET break_glass = true WHERE id = $1", [id]);
    expect((await (await oidcLogin(bg)).complete()).body.code).toBe("break_glass");
  });

  it("lets only owners, signed in, change which IdP vouches for people", async () => {
    const email = `adm@${OIDC_DOMAIN}`;
    await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "Adm", password: PASSWORD, roles: ["admin"] } });
    const t = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    const idp = (await idps()).data[0];
    expect((await h.call("PATCH", `/v1/identity-providers/${idp.id}`, { token: t, body: { mfa: "always" } })).status).toBe(403);
    expect((await h.call("DELETE", `/v1/identity-providers/${idp.id}`, { token: t })).status).toBe(403);
    expect((await h.call("GET", "/v1/identity-providers", { token: t })).status).toBe(200); // seeing them is fine
  });
});

describe("signing in with SAML", () => {
  const lin = `lin@${SAML_DOMAIN}`;

  it("needs an account when just-in-time creation is off", async () => {
    expect((await samlLogin(lin)).body).toMatchObject({ code: "no_account" });
    await h.call("POST", "/v1/users", { token: admin, body: { email: lin, given_name: "Lin", password: PASSWORD } });
    const r = await samlLogin(lin);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((await me(r.body.token)).user.email).toBe(lin);
  });

  it("refuses altered, misdirected, stale and unsigned responses", async () => {
    const reason = async (p: Promise<{ body: any }>) => (await p).body.code;
    // Altered after signing.
    expect(await reason(samlLogin(lin, (x) => x.replace(`>${lin}<`, `>root@${SAML_DOMAIN}<`)))).toBe("invalid_signature");
    // Signed by someone else.
    expect(await reason(samlLogin(lin, undefined, { key: await samlCert() }))).toBe("invalid_signature");
    // For another service provider.
    expect(await reason(samlLogin(lin, undefined, { audience: "https://other-sp.example.com" }))).toBe("invalid_response");
    // Answering another request.
    expect(await reason(samlLogin(lin, undefined, { inResponseTo: "_someone_elses_request" }))).toBe("invalid_response");
    // Signature removed.
    expect(await reason(samlLogin(lin, (x) => x.replace(/<ds:Signature[\s\S]*<\/ds:Signature>/, "")))).toBe("unsigned");
    // Expired.
    expect(await reason(samlLogin(lin, (x) => x.replace(/NotOnOrAfter="[^"]+"/g, 'NotOnOrAfter="2020-01-01T00:00:00Z"')))).toBe("invalid_signature"); // any edit breaks the signature
    // Encrypted assertions aren't supported (and say so).
    expect(await reason(samlLogin(lin, (x) => x.replace("</samlp:Response>", '<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></samlp:Response>')))).toBe("encrypted");
  });

  it("honours the assertion's time window", () => {
    const b64 = buildResponse({
      idp: SAML_IDP,
      cfg: { entity_id: sp.saml_entity_id, acs_url: sp.saml_acs_url, name_id_format: "email", sign: "assertion" },
      user: { id: "u1", email: lin, given_name: "Lin", family_name: "", department: "", title: "" } as never,
      groups: [],
      inResponseTo: "_req1",
      sessionIndex: "s1",
      authnInstant: new Date(),
      cert: samlKey,
    });
    const check = (now: Date) => verifySamlResponse(b64, { certs: [samlKey.certPem], idpEntityId: SAML_IDP, spEntityId: sp.saml_entity_id, acsUrl: sp.saml_acs_url, requestId: "_req1", now });
    expect(check(new Date()).email).toBe(lin);
    expect(() => check(new Date(Date.now() + 60 * 60_000))).toThrow(/expired/);
    expect(() => check(new Date(Date.now() - 60 * 60_000))).toThrow(/expired|isn't valid yet/);
  });

  it("isn't fooled by signature wrapping", async () => {
    const evil = `root@${SAML_DOMAIN}`;
    // The genuine signed assertion is hidden in Extensions; an attacker's copy (with its signature, now pointing elsewhere) is the one in plain sight.
    const wrapped = await samlLogin(lin, (xml) => {
      const a = xml.match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/)![0];
      const forged = a.replace(/ID="[^"]+"/, 'ID="_forged"').split(lin).join(evil);
      return xml.replace(a, `${forged}`).replace("<samlp:Status>", `<samlp:Extensions>${a}</samlp:Extensions><samlp:Status>`);
    });
    expect(wrapped.status).toBe(401);
    // Same ID on both: whatever verifies, only the signed bytes are read, so it's never the attacker's email.
    const dupe = await samlLogin(lin, (xml) => {
      const a = xml.match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/)![0];
      return xml.replace(a, a.split(lin).join(evil)).replace("<samlp:Status>", `<samlp:Extensions>${a}</samlp:Extensions><samlp:Status>`);
    });
    expect(dupe.status).toBe(401); // xml-crypto refuses duplicate IDs outright
  });
});

describe("requiring the IdP", () => {
  it("needs a successful test sign-in first, which shows what came back", async () => {
    expect((await h.call("PATCH", `/v1/identity-providers/${oidcIdp}`, { token: admin, body: { required: true } })).body.code).toBe("test_first");
    const t = await h.call("POST", `/v1/identity-providers/${oidcIdp}/test`, { token: admin, body: {} });
    const u = new URL(t.body.redirect_url);
    const code = randomBytes(8).toString("hex");
    codes.set(code, { challenge: u.searchParams.get("code_challenge")!, redirectUri: u.searchParams.get("redirect_uri")!, claims: { sub: "okta|new", email: `newbie@${OIDC_DOMAIN}`, nonce: u.searchParams.get("nonce")!, amr: ["pwd"], groups: ["Everyone"] } });
    const done = await h.call("POST", "/v1/auth/federation/complete", { body: { state: t.body.state, code } });
    expect(done.body).toEqual({ purpose: "test", idp_id: oidcIdp, state: t.body.state });
    const res = await h.call("GET", `/v1/identity-providers/${oidcIdp}/tests/${t.body.state}`, { token: admin });
    expect(res.body).toMatchObject({
      done: true,
      result: { ok: true, claims: { email: `newbie@${OIDC_DOMAIN}`, groups: ["Everyone"], mfa: false }, account: { outcome: "created" }, session_mfa: "nexus_mfa" },
    });
    expect((await h.call("GET", "/v1/users?limit=200", { token: admin })).body.data.some((x: any) => x.email === `newbie@${OIDC_DOMAIN}`)).toBe(false); // a test creates nothing
    expect((await h.call("PATCH", `/v1/identity-providers/${oidcIdp}`, { token: admin, body: { required: true } })).status).toBe(200);
  });

  it("then sends passwords, passkeys, resets and invitations to the IdP (break-glass excepted)", async () => {
    const pw = await h.call("POST", "/v1/auth/login", { body: { email: `root@${OIDC_DOMAIN}`, password: PASSWORD } });
    expect(pw).toMatchObject({ status: 403, body: { code: "use_sso", provider: { name: "Okta" } } });
    expect((await h.call("POST", "/v1/auth/passkey/options", { body: { email: `root@${OIDC_DOMAIN}` } })).body.code).toBe("use_sso");
    const mails = h.deps.mailer.sent.length;
    expect((await h.call("POST", "/v1/auth/password-reset", { body: { email: `root@${OIDC_DOMAIN}` } })).status).toBe(202);
    expect(h.deps.mailer.sent.length).toBe(mails); // nothing to reset
    expect((await h.call("POST", "/v1/auth/federation/discover", { body: { email: `x@${OIDC_DOMAIN}` } })).body.required).toBe(true);

    // The break-glass account still gets in with its password.
    const rootId = (await me(admin)).user.id;
    await owner.query("UPDATE users SET break_glass = true WHERE id = $1", [rootId]);
    expect((await h.call("POST", "/v1/auth/login", { body: { email: `root@${OIDC_DOMAIN}`, password: PASSWORD } })).status).toBe(200);
    // Other domains are unaffected.
    expect((await h.call("POST", "/v1/auth/login", { body: { email: `lin@${SAML_DOMAIN}`, password: PASSWORD } })).status).toBe(200);
  });

  it("resets the test when the connection changes, and turning the IdP off lifts the requirement", async () => {
    const r = await h.call("PATCH", `/v1/identity-providers/${oidcIdp}`, { token: admin, body: { client_secret: "rotated" } });
    const idp = r.body.data.find((x: any) => x.id === oidcIdp);
    expect(idp).toMatchObject({ last_test_ok_at: null, required: true }); // still enforced; re-test before re-requiring
    const off = await h.call("PATCH", `/v1/identity-providers/${oidcIdp}`, { token: admin, body: { enabled: false } });
    expect(off.body.data.find((x: any) => x.id === oidcIdp)).toMatchObject({ enabled: false, required: false });
    expect((await h.call("POST", "/v1/auth/federation/discover", { body: { email: `x@${OIDC_DOMAIN}` } })).body.federated).toBe(false);
  });

  it("keeps each organization's IdPs to itself", async () => {
    const other = (await h.call("POST", "/v1/signup", { body: { organization_name: "Other", email: uniqueEmail("oth"), password: PASSWORD, given_name: "O" } })).body.token;
    await h.call("PATCH", "/v1/org/settings", { token: other, body: { mfa_policy: "off" } });
    expect((await h.call("GET", "/v1/identity-providers", { token: other })).body.data).toEqual([]);
    expect((await h.call("PATCH", `/v1/identity-providers/${samlIdp}`, { token: other, body: { enabled: false } })).status).toBe(404);
    const steal = await h.call("POST", "/v1/identity-providers", { token: other, body: { name: "Mine", protocol: "saml", metadata_xml: idpMetadata(SAML_IDP, "https://x.test/sso", [samlKey.certPem]), domains: [SAML_DOMAIN] } });
    expect(steal.body.code).toBe("domain_not_verified");
  });
});

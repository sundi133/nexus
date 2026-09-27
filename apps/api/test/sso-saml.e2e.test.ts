import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";
import { deflateRawSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/**
 * Drives our SAML IdP with @node-saml/node-saml (the engine behind
 * passport-saml) acting as the service provider, so signatures, audience,
 * recipient, InResponseTo and timing are validated by an independent SP.
 */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let slug = "";
let alice = "";
let aliceId = "";
const aliceEmail = uniqueEmail("alice");
const SP_ENTITY = "https://hr.example.com/saml/metadata";
const ACS = "https://hr.example.com/saml/acs";

type Created = { app: { id: string; launch_url: string; saml: { idp_sso_url: string; idp_certificate: string; idp_entity_id: string; idp_metadata_url: string } } };

function serviceProvider(app: Created, opts: Partial<ConstructorParameters<typeof SAML>[0]> = {}) {
  return new SAML({
    issuer: SP_ENTITY,
    callbackUrl: ACS,
    entryPoint: app.app.saml.idp_sso_url,
    idpCert: app.app.saml.idp_certificate,
    audience: SP_ENTITY,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    validateInResponseTo: ValidateInResponseTo.always,
    ...opts,
  });
}

/** What the console's /saml/{slug}/sso handler does with an HTTP-Redirect AuthnRequest. */
async function sso(authorizeUrl: string, token?: string) {
  const u = new URL(authorizeUrl);
  const q = new URLSearchParams({ SAMLRequest: u.searchParams.get("SAMLRequest")!, binding: "redirect" });
  if (u.searchParams.get("RelayState")) q.set("RelayState", u.searchParams.get("RelayState")!);
  const r = await h.call("GET", `/v1/sso/saml/${slug}/sso?${q}`, { token });
  expect(r.status).toBe(200);
  return r.body as { action: string; acs_url?: string; saml_response?: string; relay_state?: string | null; code?: string };
}

beforeAll(async () => {
  h = await bootApp();
  const org = await h.call("POST", "/v1/signup", { body: { organization_name: "Initrode", email: uniqueEmail("admin"), password: PASSWORD, given_name: "Ada" } });
  admin = org.body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  slug = (await h.call("GET", "/v1/me", { token: admin })).body.organization.slug;
  aliceId = (await h.call("POST", "/v1/users", { token: admin, body: { email: aliceEmail, given_name: "Alice", family_name: "O'Hara & Co", password: PASSWORD } })).body.id;
  alice = (await h.call("POST", "/v1/auth/login", { body: { email: aliceEmail, password: PASSWORD } })).body.token;
});
afterAll(() => h.close());

describe("SAML identity provider", () => {
  let app: Created;

  it("creates a SAML app from the SP's metadata", async () => {
    const sp = new SAML({ issuer: SP_ENTITY, callbackUrl: ACS, idpCert: "unused" });
    const metadata_xml = sp.generateServiceProviderMetadata(null);
    const r = await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "saml", name: "HR Portal", metadata_xml } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    app = r.body;
    expect(app.app.saml).toMatchObject({ idp_entity_id: `http://localhost:3100/saml/${slug}` });
    expect(r.body.app.saml).toMatchObject({ entity_id: SP_ENTITY, acs_url: ACS, name_id_format: "email" });
    expect(app.app.saml.idp_certificate).toContain("BEGIN CERTIFICATE");
    expect(app.app.launch_url).toBe(`http://localhost:3100/saml/${slug}/start/${app.app.id}`);
    const dupe = await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "saml", name: "HR again", entity_id: SP_ENTITY, acs_url: ACS } });
    expect(dupe.body.code).toBe("entity_taken");
  });

  it("publishes IdP metadata with the signing certificate", async () => {
    const res = await h.app.request(`/saml/${slug}/metadata`);
    const xml = await res.text();
    expect(res.headers.get("content-type")).toContain("samlmetadata+xml");
    expect(xml).toContain(`entityID="http://localhost:3100/saml/${slug}"`);
    expect(xml).toContain("HTTP-Redirect");
    expect(xml).toContain(app.app.saml.idp_certificate.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "").slice(0, 40));
  });

  it("blocks unassigned users", async () => {
    const d = await sso(await serviceProvider(app).getAuthorizeUrlAsync("rs", undefined, {}), alice);
    expect(d).toMatchObject({ action: "error", code: "not_assigned" });
  });

  it("SP-initiated sign-in: the SP validates signature, audience, recipient and InResponseTo", async () => {
    await h.call("POST", `/v1/apps/${app.app.id}/assignments`, { token: admin, body: { principals: [{ type: "user", id: aliceId }] } });
    const g = await h.call("POST", "/v1/groups", { token: admin, body: { name: "People Ops" } });
    await h.call("POST", `/v1/groups/${g.body.id}/members`, { token: admin, body: { user_ids: [aliceId] } });

    const sp = serviceProvider(app);
    const d = await sso(await sp.getAuthorizeUrlAsync("/dashboard", undefined, {}), alice);
    expect(d.action).toBe("post");
    expect(d.acs_url).toBe(ACS);
    expect(d.relay_state).toBe("/dashboard");

    const { profile } = await sp.validatePostResponseAsync({ SAMLResponse: d.saml_response!, RelayState: d.relay_state! });
    expect(profile).toMatchObject({
      nameID: aliceEmail,
      nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      issuer: `http://localhost:3100/saml/${slug}`,
      email: aliceEmail,
      firstName: "Alice",
      lastName: "O'Hara & Co", // escaped in XML, intact after parsing
      groups: "People Ops",
    });

    // Replaying the same response is refused by the SP (InResponseTo already consumed).
    await expect(sp.validatePostResponseAsync({ SAMLResponse: d.saml_response! })).rejects.toThrow();
    const audit = await h.call("GET", "/v1/audit/events?type=sso.login", { token: admin });
    expect(audit.body.data[0]).toMatchObject({ outcome: "success", details: { protocol: "saml", flow: "sp_initiated" } });
  });

  it("a response for one SP is rejected by another (audience restriction)", async () => {
    const d = await sso(await serviceProvider(app).getAuthorizeUrlAsync("", undefined, {}), alice);
    const other = serviceProvider(app, { issuer: "https://other.example.com", audience: "https://other.example.com", validateInResponseTo: ValidateInResponseTo.never });
    await expect(other.validatePostResponseAsync({ SAMLResponse: d.saml_response! })).rejects.toThrow(/audience/i);
  });

  it("tampering with the assertion breaks the signature", async () => {
    const sp = serviceProvider(app, { validateInResponseTo: ValidateInResponseTo.never });
    const d = await sso(await sp.getAuthorizeUrlAsync("", undefined, {}), alice);
    const forged = Buffer.from(Buffer.from(d.saml_response!, "base64").toString("utf8").replace(aliceEmail, "ceo@initrode.test")).toString("base64");
    await expect(sp.validatePostResponseAsync({ SAMLResponse: forged })).rejects.toThrow(/signature/i);
  });

  it("never posts to an ACS URL other than the registered one", async () => {
    const sp = serviceProvider(app, { callbackUrl: "https://evil.example.com/acs" });
    const d = await sso(await sp.getAuthorizeUrlAsync("", undefined, {}), alice);
    expect(d).toMatchObject({ action: "error", code: "invalid_acs" });
  });

  it("sends people without a session to login, and answers IsPassive with NoPassive", async () => {
    expect((await sso(await serviceProvider(app).getAuthorizeUrlAsync("", undefined, {}))).action).toBe("login");
    const passive = Buffer.from(
      deflateRawSync(
        `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_p1" Version="2.0" IssueInstant="${new Date().toISOString()}" IsPassive="true"><saml:Issuer>${SP_ENTITY}</saml:Issuer></samlp:AuthnRequest>`,
      ),
    ).toString("base64");
    const r = await h.call("GET", `/v1/sso/saml/${slug}/sso?${new URLSearchParams({ SAMLRequest: passive })}`);
    expect(r.body.action).toBe("post");
    expect(Buffer.from(r.body.saml_response, "base64").toString()).toContain("NoPassive");
  });

  it("rejects XML with a DOCTYPE (XXE)", async () => {
    const evil = Buffer.from(
      deflateRawSync(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0"><Issuer>&e;</Issuer></samlp:AuthnRequest>`),
    ).toString("base64");
    const r = await h.call("GET", `/v1/sso/saml/${slug}/sso?${new URLSearchParams({ SAMLRequest: evil })}`, { token: alice });
    expect(r.body).toMatchObject({ action: "error", code: "invalid_request" });
  });

  it("IdP-initiated sign-in from the app launcher", async () => {
    await h.call("PATCH", `/v1/apps/${app.app.id}`, { token: admin, body: { saml: { default_relay_state: "/home" } } });
    const r = await h.call("GET", `/v1/sso/saml/${slug}/start/${app.app.id}`, { token: alice });
    expect(r.body).toMatchObject({ action: "post", acs_url: ACS, relay_state: "/home" });
    const sp = serviceProvider(app, { validateInResponseTo: ValidateInResponseTo.never });
    const { profile } = await sp.validatePostResponseAsync({ SAMLResponse: r.body.saml_response });
    expect(profile!.nameID).toBe(aliceEmail);
    const launcher = await h.call("GET", "/v1/me/apps", { token: alice });
    expect(launcher.body.data).toContainEqual(expect.objectContaining({ name: "HR Portal", protocol: "saml", launch_url: app.app.launch_url }));
  });

  it("can sign the whole response too, and use persistent NameIDs", async () => {
    await h.call("PATCH", `/v1/apps/${app.app.id}`, { token: admin, body: { saml: { sign: "response_and_assertion", name_id_format: "persistent" } } });
    const sp = serviceProvider(app, { wantAuthnResponseSigned: true });
    const d = await sso(await sp.getAuthorizeUrlAsync("", undefined, {}), alice);
    const { profile } = await sp.validatePostResponseAsync({ SAMLResponse: d.saml_response! });
    expect(profile).toMatchObject({ nameID: aliceId, nameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" });
  });
});

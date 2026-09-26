import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let slug = "";
let userId = "";

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("ops");
  const org = await h.call("POST", "/v1/signup", { body: { organization_name: "Umbrella", email, password: PASSWORD, given_name: "Olga", family_name: "Ops" } });
  admin = org.body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const me = await h.call("GET", "/v1/me", { token: admin });
  slug = me.body.organization.slug;
  userId = me.body.user.id;
  await h.call("PATCH", `/v1/users/${userId}`, { token: admin, body: { department: "Platform" } });
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

const sp = (entity: string, acs: string, idpCert: string | string[], ssoUrl: string) =>
  new SAML({ issuer: entity, callbackUrl: acs, entryPoint: ssoUrl, idpCert, audience: entity, wantAssertionsSigned: true, wantAuthnResponseSigned: false, validateInResponseTo: ValidateInResponseTo.never });

async function idpInitiated(appId: string) {
  const r = await h.call("GET", `/v1/sso/saml/${slug}/start/${appId}`, { token: admin });
  expect(r.body.action).toBe("post");
  return r.body as { saml_response: string; relay_state: string | null };
}
const assign = (appId: string) => h.call("POST", `/v1/apps/${appId}/assignments`, { token: admin, body: { principals: [{ type: "user", id: userId }] } });
const metadataCerts = async () => [...(await (await h.app.request(`/saml/${slug}/metadata`)).text()).matchAll(/<ds:X509Certificate>([^<]+)</g)].map((m) => m[1]!);

describe("app catalog", () => {
  it("lists templates with their required fields", async () => {
    const r = await h.call("GET", "/v1/app-catalog", { token: admin });
    expect(r.body.data.length).toBeGreaterThanOrEqual(10);
    const aws = r.body.data.find((t: { key: string }) => t.key === "aws");
    expect(aws.fields.map((f: { key: string }) => f.key)).toEqual(["account_id", "role_name", "provider_name"]);
  });

  it("validates fields before anything is created", async () => {
    const r = await h.call("POST", "/v1/app-catalog/aws/install", { token: admin, body: { fields: { account_id: "12345", role_name: "x/../y", provider_name: "Nexus" } } });
    expect(r.status).toBe(400);
    expect(r.body.errors.map((e: { path: string }) => e.path)).toEqual(["fields.account_id", "fields.role_name"]);
  });

  it("installs AWS with the role attribute AWS requires, verified by a real SP", async () => {
    const r = await h.call("POST", "/v1/app-catalog/aws/install", {
      token: admin,
      body: { fields: { account_id: "123456789012", role_name: "NexusReadOnly", provider_name: "VotalNexus" } },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.app).toMatchObject({ catalog_key: "aws", saml: { entity_id: "urn:amazon:webservices", acs_url: "https://signin.aws.amazon.com/saml", name_id_format: "persistent" } });
    expect(r.body.setup_steps[0]).toContain(`http://localhost:3100/saml/${slug}/metadata`);
    expect(r.body.setup_steps[0]).toContain("VotalNexus");
    await assign(r.body.app.id);

    const out = await idpInitiated(r.body.app.id);
    expect(out.relay_state).toBe("https://console.aws.amazon.com/");
    const { profile } = await sp("urn:amazon:webservices", "https://signin.aws.amazon.com/saml", r.body.app.saml.idp_certificate, r.body.app.saml.idp_sso_url).validatePostResponseAsync({
      SAMLResponse: out.saml_response,
    });
    expect(profile!["https://aws.amazon.com/SAML/Attributes/Role"]).toBe("arn:aws:iam::123456789012:role/NexusReadOnly,arn:aws:iam::123456789012:saml-provider/VotalNexus");
    expect(profile!.nameID).toBe(userId);
  });

  it("installs Slack with Slack's attribute names and launch URL", async () => {
    const r = await h.call("POST", "/v1/app-catalog/slack/install", { token: admin, body: { fields: { workspace: "umbrella-corp" } } });
    expect(r.body.app).toMatchObject({ launch_url: "https://umbrella-corp.slack.com", saml: { entity_id: "https://slack.com", acs_url: "https://umbrella-corp.slack.com/sso/saml" } });
    expect(r.body.app.saml.attributes.map((a: { name: string }) => a.name)).toEqual(["User.Email", "first_name", "last_name"]);
  });

  it("installs an OIDC app (Grafana) with rendered redirect URIs and setup values", async () => {
    const r = await h.call("POST", "/v1/app-catalog/grafana/install", { token: admin, body: { fields: { host: "grafana.umbrella.test" } } });
    expect(r.body.app.oidc.redirect_uris).toEqual(["https://grafana.umbrella.test/login/generic_oauth"]);
    expect(r.body.client_secret).toMatch(/^nxcs_/);
    expect(r.body.setup_steps.join("\n")).toContain(r.body.app.oidc.client_id);
    expect(r.body.setup_steps.join("\n")).toContain(`auth_url = http://localhost:3100/oidc/${slug}/authorize`);
  });
});

describe("attribute mapping", () => {
  it("sends exactly the configured attributes; empty values are omitted", async () => {
    const created = await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "saml", name: "Custom HR", entity_id: "https://hr.umbrella.test", acs_url: "https://hr.umbrella.test/acs" } });
    const id = created.body.app.id;
    await assign(id);
    const patch = await h.call("PATCH", `/v1/apps/${id}`, {
      token: admin,
      body: {
        saml: {
          attributes: [
            { name: "mail", source: "email" },
            { name: "dept", source: "department" },
            { name: "jobTitle", source: "title" },
            { name: "tenant", source: "static", value: "umbrella" },
          ],
        },
      },
    });
    expect(patch.status).toBe(200);
    const bad = await h.call("PATCH", `/v1/apps/${id}`, { token: admin, body: { saml: { attributes: [{ name: "x", source: "static" }] } } });
    expect(bad.status).toBe(400);

    const app = patch.body;
    const { profile } = await sp("https://hr.umbrella.test", "https://hr.umbrella.test/acs", app.saml.idp_certificate, app.saml.idp_sso_url).validatePostResponseAsync({
      SAMLResponse: (await idpInitiated(id)).saml_response,
    });
    expect(profile).toMatchObject({ mail: expect.stringContaining("@"), dept: "Platform", tenant: "umbrella" });
    expect(profile).not.toHaveProperty("jobTitle"); // title is empty for this user
    expect(profile).not.toHaveProperty("firstName"); // defaults replaced, not merged
  });
});

describe("key and certificate rotation", () => {
  let appId = "";
  const ENTITY = "https://rotation.umbrella.test";
  const ACS = "https://rotation.umbrella.test/acs";

  it("rotates the OIDC signing key and keeps the old one in JWKS", async () => {
    const before = (await (await h.app.request(`/oidc/${slug}/jwks`)).json()) as { keys: { kid: string }[] };
    const r = await h.call("POST", "/v1/org/signing-keys/oidc/rotate", { token: admin });
    expect(r.status).toBe(200);
    const after = (await (await h.app.request(`/oidc/${slug}/jwks`)).json()) as { keys: { kid: string }[] };
    expect(after.keys.length).toBe(before.keys.length + 1);
    expect(after.keys.map((k) => k.kid)).toEqual(expect.arrayContaining(before.keys.map((k) => k.kid)));
    const oidc = r.body.data.filter((k: { purpose: string }) => k.purpose === "oidc");
    expect(oidc.map((k: { status: string }) => k.status).sort()).toEqual(["active", ...before.keys.map(() => "retired")].sort());
  });

  it("SAML rotation: publish next, update apps, then activate, without breaking sign-in", async () => {
    const created = await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "saml", name: "Rotation test", entity_id: ENTITY, acs_url: ACS } });
    appId = created.body.app.id;
    await assign(appId);
    const oldCert = created.body.app.saml.idp_certificate as string;
    const ssoUrl = created.body.app.saml.idp_sso_url as string;
    expect(await metadataCerts()).toHaveLength(1);

    // 1. Prepare: the next cert appears in metadata but doesn't sign yet.
    const next = await h.call("POST", "/v1/org/signing-keys/saml/next", { token: admin });
    expect(next.status).toBe(200);
    expect((await h.call("POST", "/v1/org/signing-keys/saml/next", { token: admin })).body.code).toBe("rotation_in_progress");
    const published = await metadataCerts();
    expect(published).toHaveLength(2);
    const oldOnly = sp(ENTITY, ACS, oldCert, ssoUrl);
    await expect(oldOnly.validatePostResponseAsync({ SAMLResponse: (await idpInitiated(appId)).saml_response })).resolves.toBeTruthy();

    // 2. An app that refreshed metadata trusts both certificates.
    const pemOf = (b64: string) => `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;
    const updated = sp(ENTITY, ACS, published.map(pemOf), ssoUrl);

    // 3. Activate: responses are now signed with the new cert.
    const act = await h.call("POST", "/v1/org/signing-keys/saml/activate", { token: admin });
    expect(act.body.data.filter((k: { purpose: string; status: string }) => k.purpose === "saml" && k.status === "active")).toHaveLength(1);
    const fresh = (await idpInitiated(appId)).saml_response;
    await expect(updated.validatePostResponseAsync({ SAMLResponse: fresh })).resolves.toBeTruthy();
    await expect(oldOnly.validatePostResponseAsync({ SAMLResponse: fresh })).rejects.toThrow(/signature/i);
    expect(await metadataCerts()).toHaveLength(1);

    const inbox = await h.call("GET", "/v1/me/notifications", { token: admin });
    expect(inbox.body.data.map((n: { category: string }) => n.category)).toContain("sso.certificate");
  });

  it("warns on the Overview before the certificate expires", async () => {
    await owner.query(
      "UPDATE signing_keys SET not_after = now() + interval '10 days' WHERE purpose = 'saml' AND status = 'active' AND org_id = (SELECT id FROM organizations WHERE slug = $1)",
      [slug],
    );
    const o = await h.call("GET", "/v1/overview", { token: admin });
    expect(o.body.needs_attention.find((i: { id: string }) => i.id === "saml_cert_expiring")).toMatchObject({ severity: "critical" });
  });

  it("can discard a pending rotation", async () => {
    await h.call("POST", "/v1/org/signing-keys/saml/next", { token: admin });
    expect(await metadataCerts()).toHaveLength(2);
    expect((await h.call("DELETE", "/v1/org/signing-keys/saml/next", { token: admin })).status).toBe(200);
    expect(await metadataCerts()).toHaveLength(1);
  });
});

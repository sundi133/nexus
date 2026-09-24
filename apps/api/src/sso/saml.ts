import { createRoute, z } from "@hono/zod-openapi";
import { DOMParser } from "@xmldom/xmldom";
import { sql } from "kysely";
import { randomBytes } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { SignedXml } from "xml-crypto";
import type { App, Deps, Env, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import type { Tx } from "../platform/db.js";
import { bearer, json, problemResponses } from "../schemas.js";
import { assignedAppIds } from "./apps.js";
import { activeSamlCert, certBody, publishedSamlCerts } from "./saml-cert.js";

/**
 * SAML 2.0 identity provider (SPEC SSO-02): SP-initiated (HTTP-Redirect and
 * HTTP-POST bindings) and IdP-initiated sign-in, signed assertions, metadata.
 *
 * Security posture:
 * - Responses are only ever POSTed to the ACS URL registered for the app; an
 *   AuthnRequest asking for a different URL is refused, so unsigned requests
 *   can't redirect assertions elsewhere.
 * - Assertions are signed (RSA-SHA256, exclusive c14n), audience-restricted
 *   to the SP entity ID, valid for 5 minutes, and bound to the request ID.
 * - Inbound XML is size-limited and rejected if it contains a DOCTYPE (XXE).
 */

const NS = {
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
  ds: "http://www.w3.org/2000/09/xmldsig#",
};
const NAMEID = {
  email: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
  persistent: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
} as const;
const BINDING = {
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
};
const ASSERTION_TTL_MS = 5 * 60_000;
const SKEW_MS = 60_000;
const FORCE_AUTHN_FRESH_MS = 2 * 60_000;
const MAX_XML_BYTES = 64 * 1024;

export const ATTRIBUTE_SOURCES = ["email", "given_name", "family_name", "display_name", "user_id", "department", "title", "groups", "static"] as const;

export const AttributeMapping = z
  .object({
    name: z.string().trim().min(1).max(256),
    source: z.enum(ATTRIBUTE_SOURCES),
    value: z.string().max(2048).optional().openapi({ description: "Required when source is `static`" }),
  })
  .refine((a) => a.source !== "static" || !!a.value, { message: "A static attribute needs a value", path: ["value"] })
  .openapi("SamlAttribute");
export type AttributeMapping = z.infer<typeof AttributeMapping>;

/** What apps get when no mapping is configured. */
export const DEFAULT_ATTRIBUTES: AttributeMapping[] = [
  { name: "email", source: "email" },
  { name: "firstName", source: "given_name" },
  { name: "lastName", source: "family_name" },
  { name: "displayName", source: "display_name" },
  { name: "groups", source: "groups" },
];

export type SamlConfig = {
  entity_id: string;
  acs_url: string;
  name_id_format: keyof typeof NAMEID;
  default_relay_state?: string;
  sign: "assertion" | "response_and_assertion";
  attributes?: AttributeMapping[];
};

export const idpUrls = (deps: Deps, slug: string) => {
  const base = `${deps.cfg.publicUrl}/saml/${slug}`;
  return { entityId: base, ssoUrl: `${base}/sso`, metadataUrl: `${base}/metadata` };
};

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]!);
const instant = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");
const newSamlId = () => `_${randomBytes(20).toString("hex")}`;

// ---- Parsing ------------------------------------------------------------------------

function parseXml(xml: string) {
  if (Buffer.byteLength(xml) > MAX_XML_BYTES) throw new Error("XML too large");
  if (/<!DOCTYPE/i.test(xml)) throw new Error("DOCTYPE is not allowed");
  const errors: string[] = [];
  const doc = new DOMParser({ onError: (level, msg) => void (level !== "warning" && errors.push(msg)) }).parseFromString(xml, "text/xml");
  if (errors.length || !doc.documentElement) throw new Error("Malformed XML");
  return doc;
}

export type AuthnRequest = { id: string; issuer: string; acsUrl: string | null; forceAuthn: boolean; isPassive: boolean };

export function decodeAuthnRequest(samlRequest: string, binding: "redirect" | "post"): AuthnRequest {
  const raw = Buffer.from(samlRequest, "base64");
  const xml = binding === "redirect" ? inflateRawSync(raw, { maxOutputLength: MAX_XML_BYTES }).toString("utf8") : raw.toString("utf8");
  const root = parseXml(xml).documentElement!;
  if (root.localName !== "AuthnRequest" || root.namespaceURI !== NS.samlp) throw new Error("Not a SAML AuthnRequest");
  if (root.getAttribute("Version") !== "2.0") throw new Error("Unsupported SAML version");
  const id = root.getAttribute("ID");
  const issuer = root.getElementsByTagNameNS(NS.saml, "Issuer")[0]?.textContent?.trim();
  if (!id || !issuer) throw new Error("AuthnRequest is missing ID or Issuer");
  return {
    id,
    issuer,
    acsUrl: root.getAttribute("AssertionConsumerServiceURL") || null,
    forceAuthn: root.getAttribute("ForceAuthn") === "true",
    isPassive: root.getAttribute("IsPassive") === "true",
  };
}

/** Pulls entity ID and the HTTP-POST ACS URL out of SP metadata (SPEC SSO-04). */
export function parseSpMetadata(xml: string): { entity_id: string; acs_url: string } {
  const root = parseXml(xml).documentElement!;
  if (root.localName !== "EntityDescriptor") throw new Error("Not SAML metadata (expected an EntityDescriptor)");
  const entity_id = root.getAttribute("entityID");
  const acs = Array.from(root.getElementsByTagNameNS(NS.md, "AssertionConsumerService")).filter((e) => e.getAttribute("Binding") === BINDING.post);
  const pick = acs.find((e) => e.getAttribute("isDefault") === "true") ?? acs.sort((a, b) => Number(a.getAttribute("index") ?? 0) - Number(b.getAttribute("index") ?? 0))[0];
  const acs_url = pick?.getAttribute("Location");
  if (!entity_id || !acs_url) throw new Error("Metadata needs an entityID and an HTTP-POST AssertionConsumerService");
  return { entity_id, acs_url };
}

// ---- Building + signing ------------------------------------------------------------

type User = { id: string; email: string; given_name: string; family_name: string; department: string; title: string };

function attributeValues(a: AttributeMapping, user: User, groups: string[]): string[] {
  const displayName = `${user.given_name} ${user.family_name}`.trim() || user.email;
  const v = {
    email: [user.email],
    given_name: [user.given_name],
    family_name: [user.family_name],
    display_name: [displayName],
    user_id: [user.id],
    department: [user.department],
    title: [user.title],
    groups,
    static: [a.value ?? ""],
  }[a.source];
  return v.filter((x) => x !== "");
}

function sign(xml: string, elementId: string, issuerXpath: string, cert: { certPem: string; privateKeyPem: string }) {
  const sig = new SignedXml({
    privateKey: cert.privateKeyPem,
    publicCert: cert.certPem,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });
  sig.addReference({
    xpath: `//*[@ID='${elementId}']`,
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
  });
  // Schema order: the Signature must follow the element's Issuer.
  sig.computeSignature(xml, { prefix: "ds", location: { reference: issuerXpath, action: "after" } });
  return sig.getSignedXml();
}

export function buildResponse(a: {
  idp: string;
  cfg: SamlConfig;
  user: User;
  groups: string[];
  inResponseTo: string | null;
  sessionIndex: string;
  authnInstant: Date;
  cert: { certPem: string; privateKeyPem: string };
}) {
  const now = new Date();
  const notBefore = instant(new Date(now.getTime() - SKEW_MS));
  const notOnOrAfter = instant(new Date(now.getTime() + ASSERTION_TTL_MS));
  const responseId = newSamlId();
  const assertionId = newSamlId();
  const irt = a.inResponseTo ? ` InResponseTo="${esc(a.inResponseTo)}"` : "";
  const nameId = a.cfg.name_id_format === "persistent" ? a.user.id : a.user.email;
  const attr = (name: string, values: string[]) =>
    `<saml:Attribute Name="${esc(name)}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">${values
      .map((v) => `<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">${esc(v)}</saml:AttributeValue>`)
      .join("")}</saml:Attribute>`;
  const statements = (a.cfg.attributes ?? DEFAULT_ATTRIBUTES)
    .map((m) => ({ name: m.name, values: attributeValues(m, a.user, a.groups) }))
    .filter((m) => m.values.length > 0) // omit empty attributes rather than send blank values
    .map((m) => attr(m.name, m.values))
    .join("");

  const assertion =
    `<saml:Assertion xmlns:saml="${NS.saml}" ID="${assertionId}" Version="2.0" IssueInstant="${instant(now)}">` +
    `<saml:Issuer>${esc(a.idp)}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="${NAMEID[a.cfg.name_id_format]}">${esc(nameId)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${esc(a.cfg.acs_url)}"${irt}/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${esc(a.cfg.entity_id)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${instant(a.authnInstant)}" SessionIndex="${esc(a.sessionIndex)}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    (statements ? `<saml:AttributeStatement>${statements}</saml:AttributeStatement>` : "") +
    `</saml:Assertion>`;

  let xml =
    `<samlp:Response xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${responseId}" Version="2.0" IssueInstant="${instant(now)}" Destination="${esc(a.cfg.acs_url)}"${irt}>` +
    `<saml:Issuer>${esc(a.idp)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    assertion +
    `</samlp:Response>`;

  xml = sign(xml, assertionId, `//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']`, a.cert);
  if (a.cfg.sign === "response_and_assertion") {
    xml = sign(xml, responseId, `/*[local-name(.)='Response']/*[local-name(.)='Issuer']`, a.cert);
  }
  return Buffer.from(xml).toString("base64");
}

/** An unsigned status-only response (e.g. NoPassive): tells the SP sign-in didn't happen. */
function statusResponse(idp: string, acsUrl: string, inResponseTo: string, second: string) {
  const xml =
    `<samlp:Response xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${newSamlId()}" Version="2.0" IssueInstant="${instant(new Date())}" Destination="${esc(acsUrl)}" InResponseTo="${esc(inResponseTo)}">` +
    `<saml:Issuer>${esc(idp)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="${second}"/></samlp:StatusCode></samlp:Status>` +
    `</samlp:Response>`;
  return Buffer.from(xml).toString("base64");
}

export function idpMetadata(entityId: string, ssoUrl: string, certPems: string[]) {
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<md:EntityDescriptor xmlns:md="${NS.md}" entityID="${esc(entityId)}">` +
    `<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="${NS.samlp}">` +
    certPems
      .map((pem) => `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="${NS.ds}"><ds:X509Data><ds:X509Certificate>${certBody(pem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`)
      .join("") +
    `<md:NameIDFormat>${NAMEID.email}</md:NameIDFormat><md:NameIDFormat>${NAMEID.persistent}</md:NameIDFormat>` +
    `<md:SingleSignOnService Binding="${BINDING.redirect}" Location="${esc(ssoUrl)}"/>` +
    `<md:SingleSignOnService Binding="${BINDING.post}" Location="${esc(ssoUrl)}"/>` +
    `</md:IDPSSODescriptor></md:EntityDescriptor>`
  );
}

// ---- Decision ------------------------------------------------------------------------

const SamlDecision = z
  .discriminatedUnion("action", [
    z.object({ action: z.literal("post"), acs_url: z.string(), saml_response: z.string(), relay_state: z.string().nullable() }),
    z.object({ action: z.literal("login"), reason: z.string() }),
    z.object({ action: z.literal("error"), code: z.string(), title: z.string(), message: z.string(), app_name: z.string().nullable() }),
  ])
  .openapi("SamlDecision");
type Decision = z.infer<typeof SamlDecision>;

type Org = { org_id: string; name: string };
const orgBySlug = (deps: Deps, slug: string) =>
  deps.db.unscoped(async (tx) => (await sql<Org>`SELECT * FROM nexus_org_by_slug(${slug})`.execute(tx)).rows[0]);

const pageError = (code: string, title: string, message: string, appName: string | null = null): Decision => ({ action: "error", code, title, message, app_name: appName });

async function decide(
  deps: Deps,
  slug: string,
  input: { request: AuthnRequest | null; appId: string | null; relayState: string | null },
  principal: Principal | undefined,
  meta: Env["Variables"]["meta"],
): Promise<Decision> {
  const org = await orgBySlug(deps, slug);
  if (!org) return pageError("unknown_tenant", "Unknown organization", "This sign-in link points to an organization that doesn't exist.");
  const { entityId: idp } = idpUrls(deps, slug);

  return deps.db.tenant(org.org_id, async (tx) => {
    const q = tx.selectFrom("applications").selectAll().where("protocol", "=", "saml");
    const app = input.request
      ? await q.where(sql<boolean>`config->>'entity_id' = ${input.request.issuer}`).executeTakeFirst()
      : input.appId
        ? await q.where("id", "=", input.appId).executeTakeFirst()
        : undefined;
    if (!app) return pageError("unknown_sp", "Unknown application", "The app that sent you here isn't registered with your organization.");
    const cfg = app.config as unknown as SamlConfig;
    // Never send an assertion anywhere but the registered ACS URL.
    if (input.request?.acsUrl && input.request.acsUrl !== cfg.acs_url) {
      return pageError("invalid_acs", "Misconfigured application", `${app.name} asked for an unregistered sign-in address. Ask your administrator to check the app's settings.`, app.name);
    }
    if (app.status !== "active") return pageError("app_disabled", `${app.name} is disabled`, "Your administrator has turned off sign-in to this app.", app.name);

    const relayState = input.request ? input.relayState : (input.relayState ?? cfg.default_relay_state ?? null);
    const signedIn = principal && principal.orgId === org.org_id && principal.sessionState === "active";
    if (!signedIn) {
      if (input.request?.isPassive) {
        return { action: "post", acs_url: cfg.acs_url, saml_response: statusResponse(idp, cfg.acs_url, input.request.id, "urn:oasis:names:tc:SAML:2.0:status:NoPassive"), relay_state: relayState };
      }
      return { action: "login", reason: "no_session" };
    }
    const session = await tx.selectFrom("sessions").select(["created_at"]).where("id", "=", principal.sessionId).executeTakeFirstOrThrow();
    if (input.request?.forceAuthn && Date.now() - session.created_at.getTime() > FORCE_AUTHN_FRESH_MS) return { action: "login", reason: "force_authn" };

    if (!(await assignedAppIds(tx, principal.userId)).has(app.id)) {
      await audit(tx, org.org_id, { principal, meta }, {
        type: "sso.login",
        outcome: "denied",
        target: { type: "application", id: app.id, display: app.name },
        details: { protocol: "saml", reason: "not_assigned" },
      });
      return pageError("not_assigned", `You don't have access to ${app.name}`, "Ask your administrator to assign this app to you.", app.name);
    }

    const user = await tx
      .selectFrom("users")
      .select(["id", "email", "given_name", "family_name", "department", "title"])
      .where("id", "=", principal.userId)
      .executeTakeFirstOrThrow();
    const groups = (
      await tx
        .selectFrom("group_members")
        .innerJoin("groups", "groups.id", "group_members.group_id")
        .select("groups.name")
        .where("group_members.user_id", "=", principal.userId)
        .orderBy("groups.name")
        .execute()
    ).map((g) => g.name);
    const cert = await activeSamlCert(tx, deps, org.org_id);
    const samlResponse = buildResponse({
      idp,
      cfg,
      user,
      groups,
      inResponseTo: input.request?.id ?? null,
      sessionIndex: `_${principal.sessionId.replace(/-/g, "")}`,
      authnInstant: session.created_at,
      cert,
    });
    await audit(tx, org.org_id, { principal, meta }, {
      type: "sso.login",
      target: { type: "application", id: app.id, display: app.name },
      details: { protocol: "saml", flow: input.request ? "sp_initiated" : "idp_initiated" },
    });
    return { action: "post", acs_url: cfg.acs_url, saml_response: samlResponse, relay_state: relayState };
  });
}

export function registerSamlRoutes(app: App) {
  app.get("/saml/:slug/metadata", async (c) => {
    const deps = c.get("deps");
    const slug = c.req.param("slug");
    const org = await orgBySlug(deps, slug);
    if (!org) return c.text("Not found", 404);
    const certs = await deps.db.tenant(org.org_id, (tx) => publishedSamlCerts(tx, deps, org.org_id));
    const { entityId, ssoUrl } = idpUrls(deps, slug);
    c.header("Cache-Control", "public, max-age=300");
    return c.body(idpMetadata(entityId, ssoUrl, certs), 200, { "Content-Type": "application/samlmetadata+xml" });
  });

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/sso/saml/{slug}/sso",
      tags: ["SSO (internal)"],
      summary: "SAML sign-in decision for the web tier (SP-initiated)",
      description: "The console's /saml/{slug}/sso handler forwards the SAMLRequest with the user's session and renders the result.",
      security: bearer,
      request: {
        params: z.object({ slug: z.string().max(80) }),
        query: z.object({ SAMLRequest: z.string().max(200_000), RelayState: z.string().max(1024).optional(), binding: z.enum(["redirect", "post"]).default("redirect") }),
      },
      responses: { 200: json(SamlDecision), ...problemResponses },
    }),
    async (c) => {
      const { slug } = c.req.valid("param");
      const q = c.req.valid("query");
      let request: AuthnRequest;
      try {
        request = decodeAuthnRequest(q.SAMLRequest, q.binding);
      } catch (err) {
        return c.json(pageError("invalid_request", "Invalid sign-in request", `The app sent a SAML request Nexus couldn't read (${(err as Error).message}).`), 200);
      }
      return c.json(await decide(c.get("deps"), slug, { request, appId: null, relayState: q.RelayState ?? null }, c.get("principal"), c.get("meta")), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/sso/saml/{slug}/start/{appId}",
      tags: ["SSO (internal)"],
      summary: "SAML sign-in decision for the web tier (IdP-initiated, from the app launcher)",
      security: bearer,
      request: { params: z.object({ slug: z.string().max(80), appId: z.uuid() }), query: z.object({ RelayState: z.string().max(1024).optional() }) },
      responses: { 200: json(SamlDecision), ...problemResponses },
    }),
    async (c) => {
      const { slug, appId } = c.req.valid("param");
      const { RelayState } = c.req.valid("query");
      return c.json(await decide(c.get("deps"), slug, { request: null, appId, relayState: RelayState ?? null }, c.get("principal"), c.get("meta")), 200);
    },
  );
}

export { NAMEID };

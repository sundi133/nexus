import { randomBytes } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import type { Document, Element, Node } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import { parseXml } from "../platform/xml.js";
import { FederationError, type FederatedClaims } from "./oidc-rp.js";

/**
 * SAML 2.0 service provider: Nexus signs people in with the organization's own
 * IdP (ADFS, Entra ID, Okta, Ping, Google…). SP-initiated only: every response
 * must answer a request we sent (InResponseTo), which also makes it single-use.
 *
 * Verification, in the order an attacker would probe it:
 * - XML is size-limited, DOCTYPE-free (XXE), and must hold exactly one assertion.
 * - A signature over the Response or the Assertion must verify with a
 *   configured IdP certificate (never one embedded in the message; no SHA-1).
 * - Everything is then read from the signed bytes xml-crypto returns, not from
 *   the original document, so signature-wrapping can't swap in other content.
 * - Issuer, audience, recipient, time window and InResponseTo are checked.
 */

const NS = {
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
  ds: "http://www.w3.org/2000/09/xmldsig#",
};
const MAX_RESPONSE_BYTES = 256 * 1024;
const SKEW_MS = 2 * 60_000;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" })[c]!);
const instant = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, "Z");

export const newRequestId = () => `_${randomBytes(20).toString("hex")}`;

/** HTTP-Redirect binding URL carrying a (deflated, unsigned) AuthnRequest. */
export function authnRequestUrl(a: { ssoUrl: string; spEntityId: string; acsUrl: string; requestId: string; relayState: string; loginHint?: string }) {
  const xml =
    `<samlp:AuthnRequest xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${a.requestId}" Version="2.0" IssueInstant="${instant(new Date())}"` +
    ` Destination="${esc(a.ssoUrl)}" AssertionConsumerServiceURL="${esc(a.acsUrl)}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">` +
    `<saml:Issuer>${esc(a.spEntityId)}</saml:Issuer>` +
    (a.loginHint ? `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${esc(a.loginHint)}</saml:NameID></saml:Subject>` : "") +
    `<samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>` +
    `</samlp:AuthnRequest>`;
  const u = new URL(a.ssoUrl);
  u.searchParams.set("SAMLRequest", deflateRawSync(Buffer.from(xml)).toString("base64"));
  u.searchParams.set("RelayState", a.relayState);
  return u.toString();
}

/** Our SP metadata, for the IdP admin to import. */
export function spMetadata(entityId: string, acsUrl: string) {
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    `<md:EntityDescriptor xmlns:md="${NS.md}" entityID="${esc(entityId)}">` +
    `<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="${NS.samlp}">` +
    `<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>` +
    `<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${esc(acsUrl)}" index="0" isDefault="true"/>` +
    `</md:SPSSODescriptor></md:EntityDescriptor>`
  );
}

const toPem = (b64: string) => `-----BEGIN CERTIFICATE-----\n${b64.replace(/\s+/g, "").match(/.{1,64}/g)!.join("\n")}\n-----END CERTIFICATE-----\n`;

/** Entity ID, Redirect-binding SSO URL and signing certificates from IdP metadata. */
export function parseIdpMetadata(xml: string): { entity_id: string; sso_url: string; certs: string[] } {
  let doc: Document;
  try {
    doc = parseXml(xml, 512 * 1024);
  } catch (err) {
    throw new FederationError("bad_metadata", `This isn't valid metadata XML: ${(err as Error).message}`);
  }
  const ed = doc.getElementsByTagNameNS(NS.md, "EntityDescriptor")[0];
  const idp = ed?.getElementsByTagNameNS(NS.md, "IDPSSODescriptor")[0];
  if (!ed || !idp) throw new FederationError("bad_metadata", "No IdP (IDPSSODescriptor) in this metadata");
  const sso = Array.from(idp.getElementsByTagNameNS(NS.md, "SingleSignOnService")).find((e) => e.getAttribute("Binding") === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
  if (!sso?.getAttribute("Location")) throw new FederationError("bad_metadata", "The IdP has no HTTP-Redirect sign-in endpoint");
  const certs = Array.from(idp.getElementsByTagNameNS(NS.md, "KeyDescriptor"))
    .filter((k) => !k.getAttribute("use") || k.getAttribute("use") === "signing")
    .flatMap((k) => Array.from(k.getElementsByTagNameNS(NS.ds, "X509Certificate")).map((c) => toPem(c.textContent ?? "")));
  if (!certs.length) throw new FederationError("bad_metadata", "The metadata has no signing certificate");
  return { entity_id: ed.getAttribute("entityID") ?? "", sso_url: sso.getAttribute("Location")!, certs: [...new Set(certs)] };
}

const children = (el: Element, ns: string, name: string) => Array.from(el.childNodes).filter((n): n is Element => n.nodeType === 1 && (n as Element).namespaceURI === ns && (n as Element).localName === name);
const child = (el: Element | undefined, ns: string, name: string) => (el ? children(el, ns, name)[0] : undefined);
const text = (el: Element | undefined) => el?.textContent?.trim() ?? "";

/** The assertion as covered by a valid signature, parsed from the signed bytes only. */
function signedAssertion(xml: string, root: Element, certs: string[]): Element {
  const assertions = children(root, NS.saml, "Assertion");
  if (assertions.length !== 1) throw new FederationError("invalid_response", "The response must contain exactly one assertion");
  const sigs = [...children(root, NS.ds, "Signature"), ...children(assertions[0]!, NS.ds, "Signature")];
  if (!sigs.length) throw new FederationError("unsigned", "The IdP's response isn't signed. Turn on assertion signing.");
  for (const sigNode of sigs) {
    const owner = sigNode.parentNode as Element;
    for (const cert of certs) {
      const sx = new SignedXml({ publicCert: cert }); // uses only our configured certificate, never KeyInfo
      sx.loadSignature(sigNode);
      if (/sha1$/i.test(sx.signatureAlgorithm ?? "")) throw new FederationError("weak_signature", "The IdP signs with SHA-1. Switch it to SHA-256.");
      let ok = false;
      try {
        ok = sx.checkSignature(xml);
      } catch {
        ok = false;
      }
      if (!ok) continue;
      const refs = sx.getReferences();
      const signed = sx.getSignedReferences();
      if (refs.length !== 1 || signed.length !== 1 || refs[0]!.uri !== `#${owner.getAttribute("ID")}`) continue; // must cover exactly its parent element
      const el = parseXml(signed[0]!, MAX_RESPONSE_BYTES).documentElement!;
      if (el.namespaceURI === NS.saml && el.localName === "Assertion") return el;
      if (el.namespaceURI === NS.samlp && el.localName === "Response") {
        const inner = children(el, NS.saml, "Assertion");
        if (inner.length === 1) return inner[0]!;
      }
    }
  }
  throw new FederationError("invalid_signature", "The response's signature doesn't match the IdP certificate on file");
}

const ATTR = {
  email: ["email", "mail", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"],
  given: ["firstname", "givenname", "given_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "urn:oid:2.5.4.42"],
  family: ["lastname", "surname", "sn", "family_name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "urn:oid:2.5.4.4"],
  groups: ["groups", "memberof", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"],
  methods: ["http://schemas.microsoft.com/claims/authnmethodsreferences"],
};
const MFA_CONTEXTS = [
  "http://schemas.microsoft.com/claims/multipleauthn",
  "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
  "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered",
  "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
  "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
  "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
  "urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO",
];

export function verifySamlResponse(
  samlResponse: string,
  o: { certs: string[]; idpEntityId: string; spEntityId: string; acsUrl: string; requestId: string; emailAttribute?: string; now?: Date },
): FederatedClaims {
  const now = (o.now ?? new Date()).getTime();
  let xml: string;
  let root: Element;
  try {
    xml = Buffer.from(samlResponse, "base64").toString("utf8");
    root = parseXml(xml, MAX_RESPONSE_BYTES).documentElement!;
  } catch (err) {
    throw new FederationError("invalid_response", `The IdP's response couldn't be read: ${(err as Error).message}`);
  }
  if (root.namespaceURI !== NS.samlp || root.localName !== "Response") throw new FederationError("invalid_response", "Not a SAML response");
  const code = child(child(root, NS.samlp, "Status"), NS.samlp, "StatusCode");
  if (code?.getAttribute("Value") !== "urn:oasis:names:tc:SAML:2.0:status:Success") {
    const sub = child(code, NS.samlp, "StatusCode")?.getAttribute("Value") ?? code?.getAttribute("Value") ?? "unknown";
    throw new FederationError("idp_rejected", `The IdP didn't sign you in (${sub.split(":").pop()})`);
  }
  if (root.getElementsByTagNameNS(NS.saml, "EncryptedAssertion").length) {
    throw new FederationError("encrypted", "The IdP encrypts its assertions. Turn off assertion encryption for Nexus (the connection is already TLS).");
  }
  if (root.getAttribute("InResponseTo") && root.getAttribute("InResponseTo") !== o.requestId) throw new FederationError("invalid_response", "This response answers a different sign-in");
  if (root.getAttribute("Destination") && root.getAttribute("Destination") !== o.acsUrl) throw new FederationError("invalid_response", "This response was sent to a different address");

  const a = signedAssertion(xml, root, o.certs);

  if (text(child(a, NS.saml, "Issuer")) !== o.idpEntityId) throw new FederationError("invalid_response", `The assertion is from "${text(child(a, NS.saml, "Issuer"))}", not this IdP`);
  const conditions = child(a, NS.saml, "Conditions");
  const within = (el: Element | undefined) => {
    const nb = el?.getAttribute("NotBefore");
    const noa = el?.getAttribute("NotOnOrAfter");
    if (nb && Date.parse(nb) - SKEW_MS > now) return false;
    if (noa && Date.parse(noa) + SKEW_MS <= now) return false;
    return true;
  };
  if (!conditions || !within(conditions)) throw new FederationError("expired", "The assertion has expired or isn't valid yet (check the clocks)");
  const audiences = children(conditions, NS.saml, "AudienceRestriction").flatMap((r) => children(r, NS.saml, "Audience").map(text));
  if (!audiences.includes(o.spEntityId)) throw new FederationError("invalid_response", `The assertion is for "${audiences.join(", ")}", not Nexus (${o.spEntityId})`);

  const subject = child(a, NS.saml, "Subject");
  const confirmed = children(subject!, NS.saml, "SubjectConfirmation").some((sc) => {
    const d = child(sc, NS.saml, "SubjectConfirmationData");
    return (
      sc.getAttribute("Method") === "urn:oasis:names:tc:SAML:2.0:cm:bearer" &&
      d?.getAttribute("Recipient") === o.acsUrl &&
      d.getAttribute("InResponseTo") === o.requestId &&
      !!d.getAttribute("NotOnOrAfter") &&
      within(d)
    );
  });
  if (!subject || !confirmed) throw new FederationError("invalid_response", "The assertion isn't confirmed for this sign-in (recipient, request or expiry)");
  const nameId = text(child(subject, NS.saml, "NameID"));
  if (!nameId) throw new FederationError("invalid_response", "The assertion has no NameID");

  const attrs = new Map<string, string[]>();
  for (const st of children(a, NS.saml, "AttributeStatement")) {
    for (const at of children(st, NS.saml, "Attribute")) {
      const key = (at.getAttribute("Name") ?? "").toLowerCase();
      attrs.set(key, [...(attrs.get(key) ?? []), ...children(at, NS.saml, "AttributeValue").map(text).filter(Boolean)]);
    }
  }
  const first = (names: string[]) => names.map((n) => attrs.get(n.toLowerCase())?.[0]).find(Boolean) ?? "";
  const isEmail = (v: string) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v);
  const email = o.emailAttribute ? first([o.emailAttribute]) : isEmail(nameId) ? nameId : first(ATTR.email);
  if (!isEmail(email)) throw new FederationError("no_email", "The IdP didn't send an email address (NameID or an email attribute)");

  const contexts = children(a, NS.saml, "AuthnStatement").map((s) => text(child(child(s, NS.saml, "AuthnContext"), NS.saml, "AuthnContextClassRef")));
  const methods = ATTR.methods.flatMap((n) => attrs.get(n) ?? []);
  return {
    subject: nameId,
    email: email.toLowerCase(),
    givenName: first(ATTR.given),
    familyName: first(ATTR.family),
    groups: ATTR.groups.flatMap((n) => attrs.get(n) ?? []),
    mfa: contexts.some((c) => MFA_CONTEXTS.includes(c)) || methods.some((m) => MFA_CONTEXTS.includes(m)),
    raw: { name_id: nameId, authn_context: contexts, attributes: Object.fromEntries(attrs) },
  };
}

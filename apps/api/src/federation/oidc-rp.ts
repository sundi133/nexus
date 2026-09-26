import { createHash, randomBytes } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { assertSafeUrl, networkError } from "../platform/outbound.js";

/**
 * OpenID Connect relying party: Nexus signs people in with the organization's
 * own IdP (Okta, Entra ID, Google, Auth0, Ping…). Authorization code flow with
 * PKCE, state and nonce; the ID token is verified against the IdP's published
 * keys, issuer and audience.
 */

export class FederationError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export type Discovery = { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string };

const DISCOVERY_TTL_MS = 60 * 60_000;
const discoveries = new Map<string, { at: number; doc: Discovery }>();
const jwksSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

async function getJson(url: string): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000), redirect: "error" });
  } catch (err) {
    throw new FederationError("idp_unreachable", `Couldn't reach ${new URL(url).host}: ${networkError(err)}`);
  }
  if (!res.ok) throw new FederationError("idp_unreachable", `${new URL(url).host} answered HTTP ${res.status}`);
  return res.json().catch(() => {
    throw new FederationError("idp_misconfigured", `${url} didn't return JSON`);
  });
}

/** Explains the issuer mix-ups admins make most, which the vendors' own documents don't. */
export function issuerMismatch(asked: string, said: string) {
  const entra = /^https:\/\/login\.microsoftonline\.com\//i.test(asked);
  if (entra && said.includes("{tenantid}"))
    return "That's Entra ID's multi-tenant endpoint (common, organizations or consumers). Use your tenant's issuer: https://login.microsoftonline.com/<tenant ID>/v2.0";
  if (entra && /^https:\/\/sts\.windows\.net\//i.test(said)) {
    const tenant = said.split("/")[3];
    return `That's Entra ID's v1 endpoint. Use the v2.0 issuer: https://login.microsoftonline.com/${tenant}/v2.0`;
  }
  if (said.replace(/\/+$/, "") === asked.replace(/\/+$/, "")) return `The issuer must match the IdP's exactly, including the trailing slash: "${said}"`;
  return `The IdP says its issuer is "${said}", not "${asked}"`;
}

/** The IdP's endpoints, from /.well-known/openid-configuration (cached for an hour). */
export async function discover(issuer: string, allowPrivate: boolean, fresh = false): Promise<Discovery> {
  const hit = discoveries.get(issuer);
  if (hit && !fresh && Date.now() - hit.at < DISCOVERY_TTL_MS) return hit.doc;
  const url = `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
  await assertSafeUrl(url, { allowPrivate });
  const doc = (await getJson(url)) as Partial<Discovery>;
  // OpenID Connect Discovery §4.3: the issuer in the document must be exactly the one we asked about.
  if (doc.issuer !== issuer) throw new FederationError("idp_misconfigured", issuerMismatch(issuer, String(doc.issuer ?? "")));
  for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"] as const) {
    if (typeof doc[k] !== "string") throw new FederationError("idp_misconfigured", `The IdP's configuration has no ${k}`);
    await assertSafeUrl(doc[k]!, { allowPrivate });
  }
  const out = doc as Discovery;
  discoveries.set(issuer, { at: Date.now(), doc: out });
  return out;
}

export const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};
export const randomToken = () => randomBytes(24).toString("base64url");

export function authorizeUrl(d: Discovery, a: { clientId: string; redirectUri: string; scopes: string; state: string; nonce: string; codeChallenge: string; loginHint?: string }) {
  const u = new URL(d.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", a.clientId);
  u.searchParams.set("redirect_uri", a.redirectUri);
  u.searchParams.set("scope", a.scopes);
  u.searchParams.set("state", a.state);
  u.searchParams.set("nonce", a.nonce);
  u.searchParams.set("code_challenge", a.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  if (a.loginHint) u.searchParams.set("login_hint", a.loginHint);
  return u.toString();
}

export type FederatedClaims = {
  subject: string;
  email: string;
  givenName: string;
  familyName: string;
  groups: string[];
  mfa: boolean; // the IdP says a second factor was used
  raw: Record<string, unknown>;
};

/** `amr` values that mean more than a password (RFC 8176, plus what Entra and Okta send). */
const MFA_AMR = new Set(["mfa", "otp", "hwk", "swk", "sms", "tel", "fpt", "face", "iris", "retina", "vbm", "pop", "sc"]);

export async function exchangeCode(
  d: Discovery,
  a: { clientId: string; clientSecret: string; code: string; codeVerifier: string; redirectUri: string; nonce: string },
): Promise<FederatedClaims> {
  let res: Response;
  try {
    res = await fetch(d.token_endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
        // client_secret_basic, with the RFC 6749 §2.3.1 form-encoding of both parts.
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(a.clientId)}:${encodeURIComponent(a.clientSecret)}`).toString("base64")}`,
      },
      body: new URLSearchParams({ grant_type: "authorization_code", code: a.code, redirect_uri: a.redirectUri, code_verifier: a.codeVerifier }).toString(),
      signal: AbortSignal.timeout(10_000),
      redirect: "error",
    });
  } catch (err) {
    throw new FederationError("idp_unreachable", `Couldn't reach the IdP's token endpoint: ${networkError(err)}`);
  }
  const body = (await res.json().catch(() => ({}))) as { id_token?: string; error?: string; error_description?: string };
  if (!res.ok || !body.id_token) {
    throw new FederationError("idp_rejected", `The IdP refused the sign-in code: ${body.error_description ?? body.error ?? `HTTP ${res.status}`}`);
  }

  let jwks = jwksSets.get(d.jwks_uri);
  if (!jwks) jwksSets.set(d.jwks_uri, (jwks = createRemoteJWKSet(new URL(d.jwks_uri), { timeoutDuration: 10_000 })));
  let claims: JWTPayload;
  try {
    ({ payload: claims } = await jwtVerify(body.id_token, jwks, {
      issuer: d.issuer,
      audience: a.clientId,
      algorithms: ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"],
      clockTolerance: 60,
    }));
  } catch (err) {
    throw new FederationError("invalid_token", `The IdP's ID token didn't verify: ${(err as Error).message}`);
  }
  if (claims.nonce !== a.nonce) throw new FederationError("invalid_token", "The ID token isn't for this sign-in (nonce mismatch)");
  if (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== a.clientId) throw new FederationError("invalid_token", "The ID token was issued to another client (azp)");
  return oidcClaims(claims);
}

export function oidcClaims(c: JWTPayload & Record<string, unknown>): FederatedClaims {
  const str = (v: unknown) => (typeof v === "string" ? v : "");
  if (!c.sub) throw new FederationError("invalid_token", "The ID token has no subject");
  if (c.email_verified === false || c.email_verified === "false") throw new FederationError("email_unverified", "The IdP says this email address isn't verified");
  // Entra ID often leaves `email` out; its sign-in name is the UPN.
  const email = [c.email, c.preferred_username, c.upn].map(str).find((v) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) ?? "";
  if (!email) throw new FederationError("no_email", "The IdP didn't send an email address. Add the email scope or claim.");
  const name = str(c.name).trim();
  const amr = Array.isArray(c.amr) ? c.amr.map(String) : [];
  return {
    subject: String(c.sub),
    email: email.toLowerCase(),
    givenName: str(c.given_name) || name.split(" ")[0] || "",
    familyName: str(c.family_name) || name.split(" ").slice(1).join(" "),
    groups: Array.isArray(c.groups) ? c.groups.map(String) : [],
    mfa: amr.some((m) => MFA_AMR.has(m)) || /mfa|multi/i.test(str(c.acr)),
    raw: c,
  };
}

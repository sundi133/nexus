import { createHash, timingSafeEqual } from "node:crypto";
import { createLocalJWKSet, createRemoteJWKSet, decodeJwt, importJWK, type JWK, type JWTPayload, jwtVerify } from "jose";
import type { Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";
import { assertSafeUrl, networkError } from "../platform/outbound.js";
import { publicJwks, signJwt } from "../sso/keys.js";

/**
 * Agent tokens (SPEC AGT-02/03/06). Agents get access tokens from their
 * organization's issuer with the OAuth client_credentials grant, proving
 * themselves with a client secret, a private_key_jwt assertion, or a token from
 * a workload identity provider (GitHub Actions, AWS, GCP, Kubernetes) — so no
 * static secret is needed. Tokens are short-lived and bound to the MCP
 * gateway (RFC 8707 resource); the gateway checks the agent's kill switch on
 * every call.
 */

export const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const MAX_ASSERTION_LIFETIME_SEC = 10 * 60;

export const gatewayBase = (deps: Deps, slug: string) => `${deps.cfg.apiPublicUrl}/mcp/${slug}`;
export const hashAgentSecret = (s: string) => createHash("sha256").update(s).digest("hex");

export type TokenError = { status: 400 | 401; error: string; description: string };
const err = (status: 400 | 401, error: string, description: string): TokenError => ({ status, error, description });

type AgentRow = { id: string; name: string; status: string; token_ttl_minutes: number; client_id: string };

// ---- Workload identity providers: discovery and keys (SSRF-guarded, cached) -----------

const WORKLOAD_TTL_MS = 10 * 60_000;
const workloadKeys = new Map<string, { at: number; jwks: ReturnType<typeof createRemoteJWKSet> }>();

/** The JWKS of a workload identity issuer, from its discovery document (only jwks_uri is needed). */
export async function workloadJwks(issuer: string, allowPrivate: boolean) {
  const hit = workloadKeys.get(issuer);
  if (hit && Date.now() - hit.at < WORKLOAD_TTL_MS) return hit.jwks;
  const url = `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
  await assertSafeUrl(url, { allowPrivate });
  let doc: { issuer?: string; jwks_uri?: string };
  try {
    const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(10_000), redirect: "error" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    doc = (await res.json()) as typeof doc;
  } catch (e) {
    throw new Error(`Couldn't read ${url}: ${networkError(e)}`);
  }
  if (doc.issuer !== issuer) throw new Error(`The issuer's configuration names "${doc.issuer}", not "${issuer}"`);
  if (typeof doc.jwks_uri !== "string") throw new Error("The issuer's configuration has no jwks_uri");
  const jwksUrl = await assertSafeUrl(doc.jwks_uri, { allowPrivate });
  const jwks = createRemoteJWKSet(jwksUrl, { timeoutDuration: 10_000 });
  workloadKeys.set(issuer, { at: Date.now(), jwks });
  return jwks;
}

// ---- Client authentication ---------------------------------------------------------

type Proof = { credentialId: string; kind: "secret" | "public_key" | "federated"; detail?: string };

function sameHash(a: string, b: string) {
  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");
  return x.length === y.length && timingSafeEqual(x, y);
}

async function authenticate(tx: Tx, deps: Deps, orgId: string, agent: AgentRow, form: Record<string, string>, secret: string | null, tokenEndpoint: string, issuer: string): Promise<Proof | TokenError> {
  const now = new Date();
  const creds = (await tx.selectFrom("agent_credentials").selectAll().where("agent_id", "=", agent.id).where("revoked_at", "is", null).execute()).filter((c) => !c.expires_at || c.expires_at > now);

  if (secret !== null) {
    const h = hashAgentSecret(secret);
    const c = creds.find((x) => x.kind === "secret" && sameHash(x.secret_hash!, h));
    return c ? { credentialId: c.id, kind: "secret" } : err(401, "invalid_client", "Client authentication failed");
  }

  if (form.client_assertion_type !== ASSERTION_TYPE || !form.client_assertion) return err(401, "invalid_client", "Authenticate with client_secret or a client_assertion");
  let unverified: JWTPayload;
  try {
    unverified = decodeJwt(form.client_assertion);
  } catch {
    return err(401, "invalid_client", "The client_assertion isn't a JWT");
  }

  // private_key_jwt (RFC 7523): the agent signs its own assertion.
  if (unverified.iss === agent.client_id) {
    for (const c of creds.filter((x) => x.kind === "public_key")) {
      try {
        const key = await importJWK(c.public_jwk as JWK, (c.public_jwk as JWK).alg ?? "ES256");
        const { payload } = await jwtVerify(form.client_assertion, key, { issuer: agent.client_id, subject: agent.client_id, audience: [tokenEndpoint, issuer], requiredClaims: ["exp", "jti"], algorithms: ["ES256", "ES384", "EdDSA", "RS256", "PS256"] });
        if (payload.exp! - Math.floor(Date.now() / 1000) > MAX_ASSERTION_LIFETIME_SEC) return err(401, "invalid_client", "The client_assertion must expire within 10 minutes");
        // Single use: a replayed assertion is refused.
        const fresh = await tx
          .insertInto("agent_assertion_jtis")
          .values({ org_id: orgId, jti: `${agent.id}:${payload.jti}`, expires_at: new Date(payload.exp! * 1000) })
          .onConflict((oc) => oc.doNothing())
          .returning("jti")
          .executeTakeFirst();
        if (!fresh) return err(401, "invalid_client", "This client_assertion was already used");
        return { credentialId: c.id, kind: "public_key" };
      } catch {
        // try the next key
      }
    }
    return err(401, "invalid_client", "The client_assertion's signature doesn't match any of the agent's keys");
  }

  // Workload identity federation: a token from a trusted issuer, for an exact subject.
  const fed = creds.filter((x) => x.kind === "federated" && x.fed_issuer === unverified.iss);
  if (!fed.length) return err(401, "invalid_client", `No federated credential trusts the issuer ${String(unverified.iss ?? "(none)")}`);
  let jwks: Awaited<ReturnType<typeof workloadJwks>>;
  try {
    jwks = await workloadJwks(String(unverified.iss), deps.cfg.allowPrivateOutbound);
  } catch (e) {
    return err(401, "invalid_client", (e as Error).message);
  }
  for (const c of fed) {
    try {
      const { payload } = await jwtVerify(form.client_assertion, jwks, { issuer: c.fed_issuer!, audience: c.fed_audience!, subject: c.fed_subject!, requiredClaims: ["exp"] });
      return { credentialId: c.id, kind: "federated", detail: String(payload.sub) };
    } catch {
      // next
    }
  }
  return err(401, "invalid_client", "The workload token didn't match a federated credential (issuer, subject, audience and signature must all match)");
}

// ---- The client_credentials grant ----------------------------------------------------

export async function agentClientCredentials(
  tx: Tx,
  deps: Deps,
  a: { orgId: string; slug: string; issuer: string; form: Record<string, string>; clientId: string; secret: string | null; meta: RequestMeta },
): Promise<{ ok: true; body: Record<string, unknown> } | { ok: false; e: TokenError }> {
  const agent = await tx.selectFrom("ai_agents").select(["id", "name", "status", "token_ttl_minutes", "client_id", "owner_user_id"]).where("client_id", "=", a.clientId).executeTakeFirst();
  if (!agent) return { ok: false, e: err(401, "invalid_client", "Unknown client") };
  const proof = await authenticate(tx, deps, a.orgId, agent, a.form, a.secret, `${a.issuer}/token`, a.issuer);
  if ("error" in proof) return { ok: false, e: proof };
  if (agent.status !== "active") return { ok: false, e: err(400, "invalid_grant", "This agent is suspended") };

  // Audience: the organization's MCP gateway, or one server behind it (RFC 8707 resource).
  const base = gatewayBase(deps, a.slug);
  const resource = a.form.resource ?? base;
  if (resource !== base && !resource.startsWith(`${base}/`)) return { ok: false, e: err(400, "invalid_target", `resource must be ${base} or a server under it`) };
  const scope = (a.form.scope ?? "mcp").split(" ").filter(Boolean);
  if (scope.some((s) => s !== "mcp")) return { ok: false, e: err(400, "invalid_scope", "The only scope is mcp") };

  const ttl = agent.token_ttl_minutes * 60;
  const jti = newId();
  const token = await signJwt(tx, deps, a.orgId, { iss: a.issuer, sub: agent.id, aud: resource, client_id: agent.client_id, scope: "mcp", jti, nexus_principal: "agent" }, { typ: "at+jwt", expiresInSec: ttl });
  const now = new Date();
  await tx.updateTable("ai_agents").set({ last_token_at: now, last_seen_at: now }).where("id", "=", agent.id).execute();
  await tx.updateTable("agent_credentials").set({ last_used_at: now }).where("id", "=", proof.credentialId).execute();
  await tx.deleteFrom("agent_assertion_jtis").where("expires_at", "<", now).execute();
  await audit(tx, a.orgId, { meta: a.meta }, {
    type: "agent.token_issued",
    actor: { type: "agent", id: agent.id, display: agent.name },
    target: { type: "agent", id: agent.id, display: agent.name },
    details: { credential: proof.kind, credential_id: proof.credentialId, ...(proof.detail ? { workload: proof.detail } : {}), audience: resource, expires_in: ttl, jti },
  });
  return { ok: true, body: { access_token: token, token_type: "Bearer", expires_in: ttl, scope: "mcp" } };
}

// ---- Verification at the gateway --------------------------------------------------------

export type AgentPrincipal = { agentId: string; name: string; tags: string[]; riskTier: string; jti: string };

/**
 * Checks an agent's access token for a gateway URL: signature, issuer, audience,
 * expiry — and, from the database on every call, that the agent is still active
 * and the token was issued after its last kill switch.
 */
export async function verifyAgentToken(tx: Tx, deps: Deps, orgId: string, a: { token: string; issuer: string; slug: string; serverUrl: string }): Promise<AgentPrincipal | { error: string }> {
  const jwks = createLocalJWKSet(await publicJwks(tx, deps, orgId));
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(a.token, jwks, { issuer: a.issuer, audience: [gatewayBase(deps, a.slug), a.serverUrl], typ: "at+jwt" }));
  } catch {
    return { error: "The access token is invalid, expired, or for another resource" };
  }
  if (payload.nexus_principal !== "agent" || !payload.sub) return { error: "Only agent tokens are accepted here" };
  const agent = await tx.selectFrom("ai_agents").select(["id", "name", "status", "tokens_valid_after", "tags", "risk_tier"]).where("id", "=", payload.sub).executeTakeFirst();
  if (!agent) return { error: "Unknown agent" };
  if (agent.status !== "active") return { error: "This agent is suspended" };
  // iat has one-second resolution: a token from the same second as the kill switch is refused too.
  if ((payload.iat ?? 0) <= Math.floor(agent.tokens_valid_after.getTime() / 1000)) return { error: "This token was revoked" };
  return { agentId: agent.id, name: agent.name, tags: agent.tags, riskTier: agent.risk_tier, jti: String(payload.jti ?? "") };
}

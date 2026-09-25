import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { cors } from "hono/cors";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { agentClientCredentials } from "../ai-agents/tokens.js";
import { sql } from "kysely";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { App, Deps, Env, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { hashToken } from "../auth/tokens.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";
import { bearer, json, problemResponses } from "../schemas.js";
import { assignedAppIds, hashSecret, issuerFor } from "./apps.js";
import { publicJwks, signJwt } from "./keys.js";
import { decideAccess, matchedSummary } from "../access/service.js";

/**
 * OpenID Connect provider (SPEC SSO-01): authorization code flow with PKCE,
 * client_secret_basic/post, discovery, JWKS and userinfo. One issuer per
 * tenant at `{web origin}/oidc/{slug}`; the web tier serves /authorize with the
 * user's session and proxies everything else here.
 *
 * Deliberately small: no implicit/hybrid flows, no refresh tokens yet, RS256
 * only. Every rule below maps to a MUST in OIDC Core / RFC 6749 / RFC 7636.
 */

const CODE_TTL_MS = 60_000;
const TOKEN_TTL_SEC = 3600;

const decodeJwtSafe = (t: string) => {
  try {
    return decodeJwt(t);
  } catch {
    return null;
  }
};
const SUPPORTED_SCOPES = ["openid", "profile", "email", "groups"];

const b64u = (b: Buffer) => b.toString("base64url");
const s256 = (v: string) => b64u(createHash("sha256").update(v).digest());

type Org = { org_id: string; name: string };

async function orgBySlug(deps: Deps, slug: string): Promise<Org | undefined> {
  return deps.db.unscoped(async (tx) => (await sql<Org>`SELECT * FROM nexus_org_by_slug(${slug})`.execute(tx)).rows[0]);
}

function oauthError(c: Context<Env>, status: 400 | 401, error: string, description: string) {
  c.header("Cache-Control", "no-store");
  if (status === 401) c.header("WWW-Authenticate", `Basic realm="nexus", error="${error}"`);
  return c.json({ error, error_description: description }, status);
}

type Claims = Record<string, unknown>;

async function userClaims(tx: Tx, userId: string, scopes: Set<string>): Promise<Claims | null> {
  const u = await tx.selectFrom("users").select(["id", "email", "given_name", "family_name", "status"]).where("id", "=", userId).executeTakeFirst();
  if (!u || u.status !== "active") return null;
  const claims: Claims = { sub: u.id };
  if (scopes.has("email")) Object.assign(claims, { email: u.email, email_verified: true });
  if (scopes.has("profile")) {
    Object.assign(claims, {
      name: `${u.given_name} ${u.family_name}`.trim() || u.email,
      given_name: u.given_name,
      family_name: u.family_name,
      preferred_username: u.email,
    });
  }
  if (scopes.has("groups")) {
    const groups = await tx
      .selectFrom("group_members")
      .innerJoin("groups", "groups.id", "group_members.group_id")
      .select("groups.name")
      .where("group_members.user_id", "=", userId)
      .orderBy("groups.name")
      .execute();
    claims.groups = groups.map((g) => g.name);
  }
  return claims;
}

/** Constant-time comparison of a presented secret against its stored SHA-256. */
function secretMatches(presented: string, stored: Buffer) {
  const h = hashSecret(presented);
  return h.length === stored.length && timingSafeEqual(h, stored);
}

function clientAuth(c: Context<Env>, form: Record<string, string>) {
  const header = c.req.header("authorization");
  if (header?.startsWith("Basic ")) {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    const i = decoded.indexOf(":");
    if (i < 0) return null;
    return { id: decodeURIComponent(decoded.slice(0, i)), secret: decodeURIComponent(decoded.slice(i + 1)), method: "basic" as const };
  }
  if (form.client_id) return { id: form.client_id, secret: form.client_secret ?? null, method: form.client_secret ? ("post" as const) : ("none" as const) };
  return null;
}

// ---- Authorization decision (called by the web tier with the user's session) -------

const AuthorizeDecision = z
  .discriminatedUnion("action", [
    z.object({ action: z.literal("redirect"), location: z.string() }),
    z.object({ action: z.literal("login"), reason: z.string() }),
    z.object({ action: z.literal("device_check"), reason: z.string(), app_name: z.string() }),
    z.object({ action: z.literal("mfa"), reason: z.string(), app_name: z.string() }),
    z.object({ action: z.literal("error"), code: z.string(), title: z.string(), message: z.string(), app_name: z.string().nullable() }),
  ])
  .openapi("AuthorizeDecision");

type Decision = z.infer<typeof AuthorizeDecision>;

function redirectWith(redirectUri: string, params: Record<string, string | undefined>) {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  return url.toString();
}

async function decide(deps: Deps, slug: string, q: Record<string, string>, principal: Principal | undefined, meta: Env["Variables"]["meta"]): Promise<Decision> {
  const pageError = (code: string, title: string, message: string, appName: string | null = null): Decision => ({ action: "error", code, title, message, app_name: appName });

  const org = await orgBySlug(deps, slug);
  if (!org) return pageError("unknown_tenant", "Unknown organization", "This sign-in link points to an organization that doesn't exist.");
  const issuer = issuerFor(deps, slug);

  return deps.db.tenant(org.org_id, async (tx) => {
    // Until client and redirect_uri are validated, never redirect anywhere (open-redirect protection).
    const client = q.client_id
      ? await tx.selectFrom("applications").selectAll().where("client_id", "=", q.client_id).where("protocol", "=", "oidc").executeTakeFirst()
      : undefined;
    if (!client) return pageError("invalid_client", "Unknown application", "The app that sent you here isn't registered with your organization.");
    if (!q.redirect_uri || !client.redirect_uris.includes(q.redirect_uri)) {
      return pageError("invalid_redirect_uri", "Misconfigured application", `${client.name} sent an unregistered redirect address. Ask your administrator to check the app's settings.`, client.name);
    }
    const back = (params: Record<string, string>) => ({ action: "redirect" as const, location: redirectWith(q.redirect_uri!, { ...params, state: q.state, iss: issuer }) });

    if (client.status !== "active") return pageError("app_disabled", `${client.name} is disabled`, "Your administrator has turned off sign-in to this app.", client.name);
    if (q.response_type !== "code") return back({ error: "unsupported_response_type", error_description: "Only response_type=code is supported" });
    const scopes = new Set((q.scope ?? "").split(" ").filter(Boolean));
    if (!scopes.has("openid")) return back({ error: "invalid_scope", error_description: "The openid scope is required" });
    if (q.code_challenge_method && q.code_challenge_method !== "S256") return back({ error: "invalid_request", error_description: "Only S256 PKCE is supported" });
    if (!client.client_secret_hash && !q.code_challenge) return back({ error: "invalid_request", error_description: "Public clients must use PKCE" });
    if (q.request || q.request_uri) return back({ error: "request_not_supported", error_description: "Request objects are not supported" });

    const prompt = new Set((q.prompt ?? "").split(" ").filter(Boolean));
    const needLogin = (reason: string): Decision => (prompt.has("none") ? back({ error: "login_required" }) : { action: "login", reason });

    // A session from a different organization doesn't count here.
    if (!principal || principal.orgId !== org.org_id) return needLogin("no_session");
    if (principal.sessionState !== "active") return needLogin("incomplete_sign_in");
    if (prompt.has("login")) return needLogin("prompt_login");
    const session = await tx.selectFrom("sessions").select(["created_at", "mfa_at"]).where("id", "=", principal.sessionId).executeTakeFirstOrThrow();
    const authTime = session.created_at;
    if (q.max_age !== undefined && (Date.now() - authTime.getTime()) / 1000 > Number(q.max_age)) return needLogin("max_age");

    if (!(await assignedAppIds(tx, principal.userId)).has(client.id)) {
      if (prompt.has("none")) return back({ error: "access_denied", error_description: "The user is not assigned to this application" });
      await audit(tx, org.org_id, { principal, meta }, {
        type: "sso.login",
        outcome: "denied",
        target: { type: "application", id: client.id, display: client.name },
        details: { protocol: "oidc", reason: "not_assigned" },
      });
      return pageError("not_assigned", `You don't have access to ${client.name}`, "Ask your administrator to assign this app to you.", client.name);
    }

    // Conditional access: after assignment, before anything is issued.
    const access = await decideAccess(tx, principal, client, meta);
    if (access.outcome === "needs_device") {
      return prompt.has("none") ? back({ error: "interaction_required", error_description: access.reason }) : { action: "device_check", reason: access.reason, app_name: client.name };
    }
    if (access.outcome === "needs_mfa") {
      return prompt.has("none") ? back({ error: "interaction_required", error_description: access.reason }) : { action: "mfa", reason: access.reason, app_name: client.name };
    }
    if (access.outcome === "block") {
      await audit(tx, org.org_id, { principal, meta }, {
        type: "sso.login",
        outcome: "denied",
        target: { type: "application", id: client.id, display: client.name },
        details: { protocol: "oidc", reason: "access_policy", explanation: access.reason, policies: matchedSummary(access) },
      });
      if (prompt.has("none")) return back({ error: "access_denied", error_description: access.reason });
      return pageError("access_denied", `Access to ${client.name} is blocked`, access.reason, client.name);
    }

    const code = `nxc_${randomBytes(32).toString("base64url")}`;
    await tx
      .insertInto("oidc_codes")
      .values({
        id: newId(),
        org_id: org.org_id,
        code_hash: hashToken(code),
        app_id: client.id,
        user_id: principal.userId,
        session_id: principal.sessionId,
        redirect_uri: q.redirect_uri,
        scope: [...scopes].filter((s) => SUPPORTED_SCOPES.includes(s)).join(" "),
        nonce: q.nonce ?? null,
        code_challenge: q.code_challenge ?? null,
        auth_time: authTime,
        amr: session.mfa_at ? ["pwd", "mfa"] : ["pwd"],
        expires_at: new Date(Date.now() + CODE_TTL_MS),
      })
      .execute();
    await audit(tx, org.org_id, { principal, meta }, {
      type: "sso.login",
      target: { type: "application", id: client.id, display: client.name },
      details: { protocol: "oidc", scopes: [...scopes], policies: matchedSummary(access) },
    });
    return back({ code });
  });
}

export function registerOidcRoutes(app: App) {
  // Browser JS (SPAs) may fetch discovery, JWKS, token and userinfo cross-origin; none of them use cookies.
  app.use("/oidc/*", cors({ origin: "*", allowHeaders: ["Authorization", "Content-Type"], maxAge: 600 }));

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/sso/oidc/{slug}/authorize",
      tags: ["SSO (internal)"],
      summary: "Authorization decision for the web tier",
      description:
        "Used by the console's /oidc/{slug}/authorize handler, which attaches the signed-in user's session. Returns where to send the browser: back to the app with a code or error, to the Nexus login page, or to an error page.",
      security: bearer,
      request: {
        params: z.object({ slug: z.string().max(80) }),
        // Standard authorization request parameters; unknown ones are ignored per OAuth 2.0.
        query: z
          .object({
            client_id: z.string(),
            redirect_uri: z.string(),
            response_type: z.string(),
            scope: z.string(),
            state: z.string(),
            nonce: z.string(),
            code_challenge: z.string(),
            code_challenge_method: z.string(),
            prompt: z.string(),
            max_age: z.string(),
            request: z.string(),
            request_uri: z.string(),
          })
          .partial()
          .catchall(z.string()),
      },
      responses: { 200: json(AuthorizeDecision), ...problemResponses },
    }),
    async (c) => {
      const { slug } = c.req.valid("param");
      const decision = await decide(c.get("deps"), slug, c.req.valid("query") as Record<string, string>, c.get("principal"), c.get("meta"));
      return c.json(decision, 200);
    },
  );

  app.get("/oidc/:slug/.well-known/openid-configuration", async (c) => {
    const slug = c.req.param("slug");
    const deps = c.get("deps");
    if (!(await orgBySlug(deps, slug))) return c.json({ error: "not_found" }, 404);
    const issuer = issuerFor(deps, slug);
    c.header("Cache-Control", "public, max-age=300");
    return c.json({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ["code"],
      response_modes_supported: ["query"],
      grant_types_supported: ["authorization_code", "client_credentials"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
      token_endpoint_auth_signing_alg_values_supported: ["ES256", "ES384", "EdDSA", "RS256", "PS256"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: [...SUPPORTED_SCOPES, "mcp"],
      claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "email", "email_verified", "name", "given_name", "family_name", "preferred_username", "groups"],
      prompt_values_supported: ["none", "login"],
      authorization_response_iss_parameter_supported: true,
      request_parameter_supported: false,
      claims_parameter_supported: false,
    });
  });

  app.get("/oidc/:slug/jwks", async (c) => {
    const deps = c.get("deps");
    const org = await orgBySlug(deps, c.req.param("slug"));
    if (!org) return c.json({ error: "not_found" }, 404);
    const jwks = await deps.db.tenant(org.org_id, (tx) => publicJwks(tx, deps, org.org_id));
    c.header("Cache-Control", "public, max-age=300");
    return c.json(jwks);
  });

  app.post("/oidc/:slug/token", async (c) => {
    const deps = c.get("deps");
    const slug = c.req.param("slug");
    const org = await orgBySlug(deps, slug);
    if (!org) return oauthError(c, 400, "invalid_request", "Unknown issuer");
    const form = Object.fromEntries(Object.entries(await c.req.parseBody()).map(([k, v]) => [k, String(v)]));
    if (form.grant_type === "client_credentials") {
      // AI agents (AGT-02): a secret, a private_key_jwt, or a workload identity token.
      const basic = clientAuth(c, form);
      let clientId = basic?.id ?? form.client_id;
      if (!clientId && form.client_assertion) clientId = String(decodeJwtSafe(form.client_assertion)?.iss ?? "");
      if (!clientId?.startsWith("agt_")) return oauthError(c, 401, "invalid_client", "client_credentials is for registered agents");
      const r = await deps.db.tenant(org.org_id, (tx) =>
        agentClientCredentials(tx, deps, { orgId: org.org_id, slug, issuer: issuerFor(deps, slug), form, clientId, secret: basic?.secret ?? null, meta: c.get("meta") }),
      );
      if (!r.ok) return oauthError(c, r.e.status, r.e.error, r.e.description);
      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json(r.body);
    }
    if (form.grant_type !== "authorization_code") return oauthError(c, 400, "unsupported_grant_type", "Only authorization_code is supported");
    const auth = clientAuth(c, form);
    if (!auth) return oauthError(c, 401, "invalid_client", "Client authentication is required");
    const issuer = issuerFor(deps, slug);

    return deps.db.tenant(org.org_id, async (tx) => {
      const client = await tx.selectFrom("applications").selectAll().where("client_id", "=", auth.id).where("protocol", "=", "oidc").executeTakeFirst();
      if (!client || client.status !== "active") return oauthError(c, 401, "invalid_client", "Unknown or disabled client");
      if (client.client_secret_hash) {
        if (!auth.secret || !secretMatches(auth.secret, client.client_secret_hash)) return oauthError(c, 401, "invalid_client", "Client authentication failed");
      } else if (auth.secret) {
        return oauthError(c, 401, "invalid_client", "This is a public client; don't send a secret");
      }

      // Consume the code atomically: a code works exactly once.
      const code = await tx
        .updateTable("oidc_codes")
        .set({ used_at: new Date() })
        .where("code_hash", "=", hashToken(form.code ?? ""))
        .where("used_at", "is", null)
        .returningAll()
        .executeTakeFirst();
      if (!code || code.app_id !== client.id || code.expires_at < new Date()) return oauthError(c, 400, "invalid_grant", "The code is invalid, expired or already used");
      if (form.redirect_uri !== code.redirect_uri) return oauthError(c, 400, "invalid_grant", "redirect_uri doesn't match the authorization request");
      if (code.code_challenge) {
        if (!form.code_verifier || s256(form.code_verifier) !== code.code_challenge) return oauthError(c, 400, "invalid_grant", "PKCE verification failed");
      } else if (form.code_verifier) {
        return oauthError(c, 400, "invalid_grant", "code_verifier sent but no code_challenge was used");
      }

      const scopes = new Set(code.scope.split(" "));
      const claims = await userClaims(tx, code.user_id, scopes);
      if (!claims) return oauthError(c, 400, "invalid_grant", "The user is no longer active");
      // The session that authorized must still be alive (a revoked/contained session can't mint tokens).
      if (code.session_id) {
        const s = await tx.selectFrom("sessions").select("revoked_at").where("id", "=", code.session_id).executeTakeFirst();
        if (!s || s.revoked_at) return oauthError(c, 400, "invalid_grant", "The sign-in session was revoked");
      }

      const accessToken = await signJwt(
        tx,
        deps,
        org.org_id,
        { iss: issuer, sub: code.user_id, aud: `${issuer}/userinfo`, client_id: client.client_id, scope: code.scope, jti: newId() },
        { typ: "at+jwt", expiresInSec: TOKEN_TTL_SEC },
      );
      const atHash = b64u(createHash("sha256").update(accessToken).digest().subarray(0, 16));
      const idToken = await signJwt(
        tx,
        deps,
        org.org_id,
        {
          ...claims,
          iss: issuer,
          aud: client.client_id!,
          azp: client.client_id!,
          auth_time: Math.floor(code.auth_time.getTime() / 1000),
          amr: code.amr,
          at_hash: atHash,
          ...(code.nonce ? { nonce: code.nonce } : {}),
        },
        { expiresInSec: TOKEN_TTL_SEC },
      );
      c.header("Cache-Control", "no-store");
      c.header("Pragma", "no-cache");
      return c.json({ access_token: accessToken, token_type: "Bearer", expires_in: TOKEN_TTL_SEC, id_token: idToken, scope: code.scope });
    });
  });

  const userinfo = async (c: Context<Env>) => {
    const deps = c.get("deps");
    const slug = c.req.param("slug")!;
    const org = await orgBySlug(deps, slug);
    const header = c.req.header("authorization");
    const fail = () => {
      c.header("WWW-Authenticate", 'Bearer error="invalid_token"');
      return c.json({ error: "invalid_token" }, 401);
    };
    if (!org || !header?.startsWith("Bearer ")) return fail();
    const issuer = issuerFor(deps, slug);
    return deps.db.tenant(org.org_id, async (tx) => {
      const jwks = createLocalJWKSet(await publicJwks(tx, deps, org.org_id));
      const verified = await jwtVerify(header.slice(7), jwks, { issuer, audience: `${issuer}/userinfo`, typ: "at+jwt" }).catch(() => null);
      if (!verified?.payload.sub) return fail();
      const claims = await userClaims(tx, verified.payload.sub, new Set(String(verified.payload.scope ?? "").split(" ")));
      if (!claims) return fail();
      c.header("Cache-Control", "no-store");
      return c.json(claims);
    });
  };
  app.get("/oidc/:slug/userinfo", userinfo);
  app.post("/oidc/:slug/userinfo", userinfo);
}


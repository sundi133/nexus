import { createHash, randomBytes } from "node:crypto";
import type { JWTPayload } from "jose";
import { sql } from "kysely";
import type { Deps, Principal, RequestMeta } from "../context.js";
import { decideAccess } from "../access/service.js";
import { gatewayBase } from "../ai-agents/tokens.js";
import { audit } from "../audit/record.js";
import { hashToken } from "../auth/tokens.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";
import { signJwt } from "../sso/keys.js";

/**
 * People's own MCP clients (Cursor, Claude Desktop, VS Code…) through the gateway, the way the
 * MCP authorization spec expects: the client registers itself (RFC 7591), the person signs in
 * through Nexus (authorization code + PKCE, with MFA and conditional access like any sign-in),
 * and the client gets a short access token for the gateway resource (RFC 8707) plus a
 * refresh token that rotates on each use. A reused refresh token (a copied one) ends the grant.
 */

export const MCP_CLIENT_PREFIX = "mcpc_";
const ACCESS_TTL_SEC = 3600;
const GRANT_DAYS = 30;
/** A fixed identity for conditional access: organization-wide policies apply to MCP clients. */
export const MCP_GATEWAY_APP = { id: "00000000-0000-4000-8000-00000000c0de", name: "MCP gateway (AI clients)" };

type OAuthError = { status: 400 | 401; error: string; description: string };
const err = (status: 400 | 401, error: string, description: string): { ok: false; e: OAuthError } => ({ ok: false, e: { status, error, description } });

// ---- Registration (RFC 7591) ------------------------------------------------------------------------

/**
 * Where a client may receive codes: this machine (loopback, any port) or an app's own scheme
 * (cursor://…, vscode://…). Never a web address: a code sent there would leave the device.
 */
export function redirectAllowed(uri: string): boolean {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.hash) return false;
  if (u.protocol === "http:") return ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname);
  if (u.protocol === "https:") return false;
  // Private-use schemes (RFC 8252 §7.1), never ones a browser would run or read.
  return /^[a-z][a-z0-9+.-]*:$/.test(u.protocol) && !["javascript:", "data:", "file:", "blob:", "about:", "vbscript:", "ftp:", "ws:", "wss:", "chrome:", "chrome-extension:"].includes(u.protocol);
}

export async function registerClient(tx: Tx, orgId: string, body: Record<string, unknown>) {
  const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter((x): x is string => typeof x === "string") : [];
  if (!uris.length || uris.length > 10) return err(400, "invalid_redirect_uri", "redirect_uris: 1 to 10 addresses");
  const bad = uris.find((u) => !redirectAllowed(u) || u.length > 500);
  if (bad) return err(400, "invalid_redirect_uri", `Only this device (http://127.0.0.1, http://localhost) or an app's own scheme can receive codes, not ${bad.slice(0, 100)}`);
  const method = body.token_endpoint_auth_method ?? "none";
  if (method !== "none") return err(400, "invalid_client_metadata", "MCP clients are public clients: token_endpoint_auth_method must be none (PKCE protects the code)");
  const grants = Array.isArray(body.grant_types) ? body.grant_types : ["authorization_code", "refresh_token"];
  if (grants.some((g) => g !== "authorization_code" && g !== "refresh_token")) return err(400, "invalid_client_metadata", "grant_types: authorization_code and refresh_token only");
  const name = (typeof body.client_name === "string" ? body.client_name.trim() : "").slice(0, 100) || "MCP client";
  const clientId = `${MCP_CLIENT_PREFIX}${randomBytes(18).toString("base64url")}`;
  await tx.insertInto("mcp_clients").values({ id: newId(), org_id: orgId, client_id: clientId, name, redirect_uris: uris, last_used_at: null }).execute();
  return {
    ok: true as const,
    body: {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: name,
      redirect_uris: uris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    },
  };
}

// ---- Authorization -----------------------------------------------------------------------------------

/** The gateway resource a client asks for: the gateway itself, or one server under it. */
async function resourceFor(tx: Tx, deps: Deps, slug: string, resource: string | undefined) {
  const base = gatewayBase(deps, slug);
  if (!resource) return null;
  const r = resource.replace(/\/+$/, "");
  if (r === base) return { resource: r, serverId: null as string | null };
  if (!r.startsWith(`${base}/`)) return null;
  const s = await tx.selectFrom("mcp_servers").select("id").where("slug", "=", r.slice(base.length + 1)).executeTakeFirst();
  return s ? { resource: r, serverId: s.id } : null;
}

/** Whether any rule lets this person use some tool (on one server, or any). */
export async function personHasTools(tx: Tx, userId: string, serverId: string | null) {
  const groups = (await tx.selectFrom("group_members").select("group_id").where("user_id", "=", userId).execute()).map((g) => g.group_id);
  let q = tx
    .selectFrom("mcp_permissions")
    .select("id")
    .where("effect", "=", "allow")
    .where((eb) => eb.or([eb("subject_type", "=", "all_people"), eb.and([eb("subject_type", "=", "user"), eb("subject_id", "=", userId)]), ...(groups.length ? [eb.and([eb("subject_type", "=", "group"), eb("subject_id", "in", groups)])] : [])]));
  if (serverId) q = q.where("server_id", "=", serverId);
  return !!(await q.limit(1).executeTakeFirst());
}

export type McpDecision =
  | { action: "redirect"; location: string }
  | { action: "login"; reason: string }
  | { action: "device_check"; reason: string; app_name: string }
  | { action: "mfa"; reason: string; app_name: string }
  | { action: "error"; code: string; title: string; message: string; app_name: string | null };

export async function decideMcpClient(
  tx: Tx,
  deps: Deps,
  a: { orgId: string; slug: string; issuer: string; q: Record<string, string>; principal: Principal | undefined; meta: RequestMeta },
): Promise<McpDecision> {
  const { q, principal } = a;
  const client = await tx.selectFrom("mcp_clients").selectAll().where("client_id", "=", q.client_id!).executeTakeFirst();
  const page = (code: string, title: string, message: string): McpDecision => ({ action: "error", code, title, message, app_name: client?.name ?? null });
  if (!client) return page("invalid_client", "Unknown AI client", "This AI client isn't registered with your organization. Remove the server from the client and add it again.");
  if (!q.redirect_uri || !client.redirect_uris.includes(q.redirect_uri)) return page("invalid_redirect_uri", "Misconfigured AI client", `${client.name} sent an unregistered redirect address.`);
  const back = (params: Record<string, string>): McpDecision => {
    const url = new URL(q.redirect_uri!);
    for (const [k, v] of Object.entries({ ...params, state: q.state, iss: a.issuer })) if (v !== undefined) url.searchParams.set(k, v);
    return { action: "redirect", location: url.toString() };
  };
  if (q.response_type !== "code") return back({ error: "unsupported_response_type", error_description: "Only response_type=code is supported" });
  if (!q.code_challenge || (q.code_challenge_method ?? "S256") !== "S256") return back({ error: "invalid_request", error_description: "PKCE with S256 is required" });
  const target = await resourceFor(tx, deps, a.slug, q.resource);
  if (!target) return back({ error: "invalid_target", error_description: `resource must be ${gatewayBase(deps, a.slug)} or an MCP server under it` });

  const prompt = new Set((q.prompt ?? "").split(" ").filter(Boolean));
  if (!principal || principal.orgId !== a.orgId || principal.sessionState !== "active" || prompt.has("login")) {
    return prompt.has("none") ? back({ error: "login_required" }) : { action: "login", reason: "no_session" };
  }
  if (!(await personHasTools(tx, principal.userId, target.serverId))) {
    await audit(tx, a.orgId, { principal, meta: a.meta }, { type: "mcp.client_authorized", outcome: "denied", target: { type: "mcp_client", id: client.id, display: client.name }, details: { resource: target.resource, reason: "no_tools" } });
    return page("no_mcp_access", "No MCP tools for you yet", "Your organization hasn't given you tools on this MCP server through Nexus. Ask your administrator.");
  }
  // Conditional access, as for any sign-in: MFA, managed or compliant devices, blocks.
  const access = await decideAccess(tx, principal, MCP_GATEWAY_APP, a.meta);
  if (access.outcome === "needs_device") return prompt.has("none") ? back({ error: "interaction_required" }) : { action: "device_check", reason: access.reason, app_name: client.name };
  if (access.outcome === "needs_mfa") return prompt.has("none") ? back({ error: "interaction_required" }) : { action: "mfa", reason: access.reason, app_name: client.name };
  if (access.outcome === "block") {
    await audit(tx, a.orgId, { principal, meta: a.meta }, { type: "mcp.client_authorized", outcome: "denied", target: { type: "mcp_client", id: client.id, display: client.name }, details: { resource: target.resource, reason: "access_policy", explanation: access.reason } });
    return page("access_denied", `${client.name} is blocked`, access.reason);
  }

  const session = await tx.selectFrom("sessions").select(["created_at", "mfa_at"]).where("id", "=", principal.sessionId).executeTakeFirstOrThrow();
  const code = `nxc_${randomBytes(32).toString("base64url")}`;
  await tx
    .insertInto("oidc_codes")
    .values({
      id: newId(),
      org_id: a.orgId,
      code_hash: hashToken(code),
      app_id: null,
      mcp_client_id: client.id,
      resource: target.resource,
      user_id: principal.userId,
      session_id: principal.sessionId,
      redirect_uri: q.redirect_uri,
      scope: "mcp",
      nonce: null,
      code_challenge: q.code_challenge,
      auth_time: session.created_at,
      amr: session.mfa_at ? ["pwd", "mfa"] : ["pwd"],
      expires_at: new Date(Date.now() + 60_000),
    })
    .execute();
  await tx.updateTable("mcp_clients").set({ last_used_at: new Date() }).where("id", "=", client.id).execute();
  await audit(tx, a.orgId, { principal, meta: a.meta }, { type: "mcp.client_authorized", target: { type: "mcp_client", id: client.id, display: client.name }, details: { resource: target.resource } });
  return back({ code });
}

// ---- Tokens ----------------------------------------------------------------------------------------

const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

async function accessToken(tx: Tx, deps: Deps, orgId: string, issuer: string, g: { userId: string; grantId: string; resource: string; clientId: string }) {
  return signJwt(tx, deps, orgId, { iss: issuer, sub: g.userId, aud: g.resource, client_id: g.clientId, scope: "mcp", jti: newId(), nexus_principal: "user", grant: g.grantId }, { typ: "at+jwt", expiresInSec: ACCESS_TTL_SEC });
}

const tokenResponse = (access: string, refresh: string) => ({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL_SEC, refresh_token: refresh, scope: "mcp" });
const newRefresh = () => `nxr_${randomBytes(32).toString("base64url")}`;

async function activeUser(tx: Tx, userId: string) {
  return tx.selectFrom("users").select(["id", "email", "status"]).where("id", "=", userId).where("status", "=", "active").executeTakeFirst();
}

export async function exchangeCode(tx: Tx, deps: Deps, a: { orgId: string; issuer: string; form: Record<string, string>; meta: RequestMeta }) {
  const { form } = a;
  const client = await tx.selectFrom("mcp_clients").selectAll().where("client_id", "=", form.client_id ?? "").executeTakeFirst();
  if (!client) return err(401, "invalid_client", "Unknown client");
  const code = await tx.updateTable("oidc_codes").set({ used_at: new Date() }).where("code_hash", "=", hashToken(form.code ?? "")).where("used_at", "is", null).returningAll().executeTakeFirst();
  if (!code || code.mcp_client_id !== client.id || code.expires_at < new Date()) return err(400, "invalid_grant", "The code is invalid, expired or already used");
  if (form.redirect_uri !== code.redirect_uri) return err(400, "invalid_grant", "redirect_uri doesn't match the authorization request");
  if (!form.code_verifier || s256(form.code_verifier) !== code.code_challenge) return err(400, "invalid_grant", "PKCE verification failed");
  if (form.resource && form.resource.replace(/\/+$/, "") !== code.resource) return err(400, "invalid_target", "resource doesn't match the authorization request");
  if (!(await activeUser(tx, code.user_id))) return err(400, "invalid_grant", "The user is no longer active");
  if (code.session_id) {
    const s = await tx.selectFrom("sessions").select("revoked_at").where("id", "=", code.session_id).executeTakeFirst();
    if (!s || s.revoked_at) return err(400, "invalid_grant", "The sign-in session was revoked");
  }
  const refresh = newRefresh();
  const grantId = newId();
  await tx
    .insertInto("mcp_grants")
    .values({ id: grantId, org_id: a.orgId, user_id: code.user_id, client_id: client.id, resource: code.resource!, refresh_hash: hashToken(refresh), previous_hash: null, expires_at: new Date(Date.now() + GRANT_DAYS * 86_400_000), revoked_at: null })
    .execute();
  const access = await accessToken(tx, deps, a.orgId, a.issuer, { userId: code.user_id, grantId, resource: code.resource!, clientId: client.client_id });
  return { ok: true as const, body: tokenResponse(access, refresh) };
}

export async function refreshGrant(tx: Tx, deps: Deps, a: { orgId: string; issuer: string; form: Record<string, string>; meta: RequestMeta }) {
  const presented = hashToken(a.form.refresh_token ?? "");
  const grant = await tx.selectFrom("mcp_grants").innerJoin("mcp_clients", "mcp_clients.id", "mcp_grants.client_id").selectAll("mcp_grants").select("mcp_clients.client_id as public_id").where("refresh_hash", "=", presented).forUpdate().executeTakeFirst();
  if (!grant) {
    // A token that was already rotated: someone kept a copy. End that grant.
    const stolen = await tx.updateTable("mcp_grants").set({ revoked_at: new Date() }).where("previous_hash", "=", presented).where("revoked_at", "is", null).returning(["id", "user_id"]).executeTakeFirst();
    if (stolen) {
      await audit(tx, a.orgId, { meta: a.meta }, { type: "mcp.grant_revoked", outcome: "failure", actor: { type: "system", id: null, display: "Nexus" }, target: { type: "user", id: stolen.user_id, display: "" }, details: { grant_id: stolen.id, reason: "refresh_token_reused" } });
    }
    return err(400, "invalid_grant", "The refresh token is invalid");
  }
  if (grant.public_id !== a.form.client_id) return err(400, "invalid_grant", "The refresh token belongs to another client");
  if (grant.revoked_at || grant.expires_at < new Date()) return err(400, "invalid_grant", "This authorization ended: sign in again");
  if (!(await activeUser(tx, grant.user_id))) return err(400, "invalid_grant", "The user is no longer active");
  if (a.form.resource && a.form.resource.replace(/\/+$/, "") !== grant.resource) return err(400, "invalid_target", "resource doesn't match the grant");
  const refresh = newRefresh();
  await tx.updateTable("mcp_grants").set({ previous_hash: presented, refresh_hash: hashToken(refresh), last_used_at: new Date() }).where("id", "=", grant.id).execute();
  const access = await accessToken(tx, deps, a.orgId, a.issuer, { userId: grant.user_id, grantId: grant.id, resource: grant.resource, clientId: grant.public_id });
  return { ok: true as const, body: tokenResponse(access, refresh) };
}

// ---- The gateway's side ----------------------------------------------------------------------------

export type UserCaller = { kind: "user"; userId: string; email: string; groupIds: string[]; grantId: string; clientName: string };

/** A person's gateway token, still backed by a live grant and an active account. */
export async function verifyUserToken(tx: Tx, payload: JWTPayload): Promise<UserCaller | { error: string }> {
  if (!payload.sub || typeof payload.grant !== "string") return { error: "The access token is incomplete" };
  const g = await tx
    .selectFrom("mcp_grants")
    .innerJoin("users", "users.id", "mcp_grants.user_id")
    .innerJoin("mcp_clients", "mcp_clients.id", "mcp_grants.client_id")
    .select(["mcp_grants.id", "mcp_grants.revoked_at", "mcp_grants.expires_at", "users.id as user_id", "users.email", "users.status", "mcp_clients.name as client_name"])
    .where("mcp_grants.id", "=", payload.grant)
    .executeTakeFirst();
  if (!g || g.user_id !== payload.sub) return { error: "Unknown authorization" };
  if (g.revoked_at || g.expires_at < new Date()) return { error: "This authorization was revoked: sign in again" };
  if (g.status !== "active") return { error: "This account is suspended" };
  const groupIds = (await tx.selectFrom("group_members").select("group_id").where("user_id", "=", g.user_id).execute()).map((x) => x.group_id);
  await sql`UPDATE mcp_grants SET last_used_at = now() WHERE id = ${g.id} AND last_used_at < now() - interval '1 minute'`.execute(tx);
  return { kind: "user", userId: g.user_id, email: g.email, groupIds, grantId: g.id, clientName: g.client_name };
}

/** Ends every AI-client authorization a person has (offboarding, containment, "sign out everywhere"). */
export async function revokeMcpGrants(tx: Tx, userId: string) {
  const r = await tx.updateTable("mcp_grants").set({ revoked_at: new Date() }).where("user_id", "=", userId).where("revoked_at", "is", null).executeTakeFirst();
  return Number(r.numUpdatedRows);
}

import type { Context, MiddlewareHandler } from "hono";
import { sql } from "kysely";
import type { Env, Principal } from "../context.js";
import { ApiError, forbidden, unauthorized } from "../platform/errors.js";
import { can, type Permission, resolveGrants, type Role, rolePermissions } from "../rbac.js";
import type { Tx } from "../platform/db.js";
import { hashToken } from "./tokens.js";
import { RateLimiter } from "./ratelimit.js";

// Per API key: generous for automation, bounded so a runaway script can't swamp a tenant.
const keyLimiter = new RateLimiter(600, 60_000, "api-key");
import type { SessionState } from "../platform/db-types.js";

type SessionLookup = {
  session_id: string;
  org_id: string;
  user_id: string;
  state: SessionState;
  client: string;
  mfa_at: Date | null;
  mfa_method: "totp" | "push" | "webauthn" | "recovery_code" | "idp" | null;
  expires_at: Date;
  user_status: string;
};

/**
 * Resolves `Authorization: Bearer nxs_…` into a Principal (or none). It never
 * rejects by itself; handlers state what they need via requireSession /
 * requirePermission, so the rule sits next to the code it protects.
 */
export const loadPrincipal: MiddlewareHandler<Env> = async (c, next) => {
  const header = c.req.header("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : null;
  if (token?.startsWith("nxk_")) {
    const { db } = c.get("deps");
    const key = await db.unscoped(async (tx) => {
      const r = await sql<{ id: string; org_id: string; name: string; scopes: string[]; created_by: string | null; last_used_at: Date | null }>`SELECT * FROM nexus_auth_api_key(${hashToken(token)})`.execute(tx);
      return r.rows[0];
    });
    if (key) {
      if (!(await keyLimiter.take(key.id))) throw new ApiError(429, "rate_limited", "This API key is sending too many requests. Slow down and retry.");
      if (!key.last_used_at || Date.now() - key.last_used_at.getTime() > 60_000) {
        const ip = c.get("meta").ip;
        await db.tenant(key.org_id, (tx) => tx.updateTable("api_keys").set({ last_used_at: new Date(), last_used_ip: ip }).where("id", "=", key.id).execute());
      }
      c.set("principal", {
        orgId: key.org_id,
        userId: key.created_by ?? "00000000-0000-0000-0000-000000000000",
        email: `API key “${key.name}”`,
        sessionId: "",
        sessionState: "active",
        client: "api",
        mfaAt: new Date(), // keys have no MFA; their scopes are the control (and step-up-worthy scopes need an admin to grant them)
        roles: [],
        apiKey: { id: key.id, name: key.name, scopes: new Set(key.scopes as Permission[]) },
      });
    }
  } else if (token?.startsWith("nxs_")) {
    const { db } = c.get("deps");
    const found = await db.unscoped(async (tx) => {
      const r = await sql<SessionLookup>`SELECT * FROM nexus_auth_session(${hashToken(token)})`.execute(tx);
      return r.rows[0];
    });
    if (found && found.user_status === "active") {
      const { roles, grants, email, ownerPasskeyRequired } = await db.tenant(found.org_id, async (tx) => {
        const rows = await tx.selectFrom("user_roles").select("role").where("user_id", "=", found.user_id).execute();
        const extra = await tx
          .selectFrom("role_grants")
          .leftJoin("custom_roles", "custom_roles.id", "role_grants.custom_role_id")
          .select(["role_grants.builtin_role", "role_grants.scope_group_ids", "custom_roles.permissions"])
          .where("role_grants.user_id", "=", found.user_id)
          .execute();
        const user = await tx.selectFrom("users").select("email").where("id", "=", found.user_id).executeTakeFirstOrThrow();
        const org = await tx.selectFrom("organizations").select("settings").where("id", "=", found.org_id).executeTakeFirstOrThrow();
        // Touch last_seen at most once a minute to keep writes cheap.
        await tx
          .updateTable("sessions")
          .set({ last_seen_at: new Date() })
          .where("id", "=", found.session_id)
          .where("last_seen_at", "<", new Date(Date.now() - 60_000))
          .execute();
        const roles = rows.map((r) => r.role as Role);
        const grants = resolveGrants(
          roles,
          extra.map((g) => ({ permissions: g.builtin_role ? rolePermissions(g.builtin_role) : (g.permissions ?? []), scope: g.scope_group_ids })),
        );
        return { roles, grants, email: user.email, ownerPasskeyRequired: (org.settings as { owners_require_passkey?: boolean }).owners_require_passkey === true };
      });
      c.set("principal", {
        orgId: found.org_id,
        userId: found.user_id,
        email,
        sessionId: found.session_id,
        sessionState: found.state,
        client: found.client,
        mfaAt: found.mfa_at,
        mfaMethod: found.mfa_method,
        ownerPasskeyRequired,
        roles,
        grants,
      });
    }
  }
  await next();
};

/**
 * Requires a fully authenticated session. Sessions still mid sign-in are only
 * accepted where the handler opts in: `allowPendingMfa` (verifying a factor)
 * or `allowEnroll` (setting up the first factor the org policy requires).
 */
export function requireSession(c: Context<Env>, opts: { allowPendingMfa?: boolean; allowEnroll?: boolean; allowApiKey?: boolean } = {}): Principal {
  const p = c.get("principal");
  if (!p) throw unauthorized();
  if (p.apiKey && !opts.allowApiKey) throw forbidden("API keys can't use personal endpoints; sign in as a person instead");
  if (p.sessionState === "pending_mfa" && !opts.allowPendingMfa) {
    throw new ApiError(401, "mfa_required", "Complete multi-factor authentication to continue");
  }
  if (p.sessionState === "enroll_mfa" && !opts.allowEnroll) {
    throw new ApiError(401, "mfa_enrollment_required", "Your organization requires you to set up multi-factor authentication");
  }
  return p;
}

/** Where the principal holds a permission: everywhere ("all"), within some groups, or not at all. */
export function scopeOf(p: Principal, perm: Permission): "all" | ReadonlySet<string> | null {
  if (p.apiKey) return p.apiKey.scopes.has(perm) ? "all" : null;
  if (p.grants) return p.grants.get(perm) ?? null;
  return principalCan(p, perm) ? "all" : null;
}

/** The principal holds the permission across the whole organization. */
export const principalCan = (p: Principal, perm: Permission) => scopeOf(p, perm) === "all";

/**
 * Requires a permission. Deny by default for scoped grants (RBAC-03): a
 * permission held only within some groups counts only where the route opts in
 * with `{ scoped: true }` — and then must limit what it touches with
 * `scopeOf` / `assertUserInScope` / `assertDeviceInScope`.
 */
export function requirePermission(c: Context<Env>, perm: Permission, opts: { scoped?: boolean } = {}): Principal {
  const p = requireSession(c, { allowApiKey: true });
  const scope = scopeOf(p, perm);
  if (!scope || (scope !== "all" && !opts.scoped)) throw forbidden(p.apiKey ? `This API key doesn't have the ${perm} scope` : undefined);
  return p;
}

/** Group IDs the principal is limited to for this permission, or null when it isn't limited. */
export function scopeGroups(p: Principal, perm: Permission): string[] | null {
  const s = scopeOf(p, perm);
  return s === "all" || !s ? null : [...s];
}

export async function isUserInScope(tx: Tx, p: Principal, perm: Permission, userId: string) {
  const groups = scopeGroups(p, perm);
  if (!groups) return scopeOf(p, perm) === "all";
  return !!(await tx.selectFrom("group_members").select("user_id").where("user_id", "=", userId).where("group_id", "in", groups).executeTakeFirst());
}

/** Scoped admins can only act on people in their groups; others don't exist for them. */
export async function assertUserInScope(tx: Tx, p: Principal, perm: Permission, userId: string) {
  if (!(await isUserInScope(tx, p, perm, userId))) throw new ApiError(404, "not_found", "User not found");
}

/** A device is in scope when its primary user is. */
export async function assertDeviceInScope(tx: Tx, p: Principal, perm: Permission, deviceId: string) {
  if (!scopeGroups(p, perm)) return;
  const d = await tx.selectFrom("devices").select("primary_user_id").where("id", "=", deviceId).executeTakeFirst();
  if (!d?.primary_user_id || !(await isUserInScope(tx, p, perm, d.primary_user_id))) throw new ApiError(404, "not_found", "Device not found");
}

const STEP_UP_WINDOW_MS = 10 * 60 * 1000;

/**
 * Sensitive actions need MFA within the last 10 minutes (SPEC AUTH-07). Users
 * with no factor enrolled yet pass, so first-time setup is possible; the
 * "Needs attention" queue pushes them to enroll.
 */
export function requireRecentMfa(c: Context<Env>, p: Principal, hasFactors: boolean, opts: { personal?: boolean } = {}) {
  if (!hasFactors || p.apiKey) return;
  // Owners confirm admin actions with a passkey when the org requires it (RBAC-04). Personal
  // actions (like adding that first passkey) accept any method, so nobody gets stuck.
  const needsPasskey = !opts.personal && !!p.ownerPasskeyRequired && p.roles.includes("owner");
  const recent = !!p.mfaAt && Date.now() - p.mfaAt.getTime() < STEP_UP_WINDOW_MS;
  if (recent && (!needsPasskey || p.mfaMethod === "webauthn")) return;
  c.header("WWW-Authenticate", 'Bearer error="insufficient_user_authentication", max_age=600');
  if (needsPasskey) throw new ApiError(401, "passkey_required", "Owners confirm admin actions with a passkey in this organization");
  throw new ApiError(401, "step_up_required", "Re-verify with MFA to perform this action");
}

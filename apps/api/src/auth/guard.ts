import type { Context, MiddlewareHandler } from "hono";
import { sql } from "kysely";
import type { Env, Principal } from "../context.js";
import { ApiError, forbidden, unauthorized } from "../platform/errors.js";
import { can, type Permission, type Role } from "../rbac.js";
import { hashToken } from "./tokens.js";
import { RateLimiter } from "./ratelimit.js";

// Per API key: generous for automation, bounded so a runaway script can't swamp a tenant.
const keyLimiter = new RateLimiter(600, 60_000);
import type { SessionState } from "../platform/db-types.js";

type SessionLookup = {
  session_id: string;
  org_id: string;
  user_id: string;
  state: SessionState;
  client: string;
  mfa_at: Date | null;
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
      if (!keyLimiter.take(key.id)) throw new ApiError(429, "rate_limited", "This API key is sending too many requests. Slow down and retry.");
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
      const { roles, email } = await db.tenant(found.org_id, async (tx) => {
        const rows = await tx.selectFrom("user_roles").select("role").where("user_id", "=", found.user_id).execute();
        const user = await tx.selectFrom("users").select("email").where("id", "=", found.user_id).executeTakeFirstOrThrow();
        // Touch last_seen at most once a minute to keep writes cheap.
        await tx
          .updateTable("sessions")
          .set({ last_seen_at: new Date() })
          .where("id", "=", found.session_id)
          .where("last_seen_at", "<", new Date(Date.now() - 60_000))
          .execute();
        return { roles: rows.map((r) => r.role as Role), email: user.email };
      });
      c.set("principal", {
        orgId: found.org_id,
        userId: found.user_id,
        email,
        sessionId: found.session_id,
        sessionState: found.state,
        client: found.client,
        mfaAt: found.mfa_at,
        roles,
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

export function requirePermission(c: Context<Env>, perm: Permission): Principal {
  const p = requireSession(c, { allowApiKey: true });
  if (p.apiKey ? !p.apiKey.scopes.has(perm) : !can(p.roles, perm)) throw forbidden(p.apiKey ? `This API key doesn't have the ${perm} scope` : undefined);
  return p;
}

const STEP_UP_WINDOW_MS = 10 * 60 * 1000;

/**
 * Sensitive actions need MFA within the last 10 minutes (SPEC AUTH-07). Users
 * with no factor enrolled yet pass, so first-time setup is possible; the
 * "Needs attention" queue pushes them to enroll.
 */
export function requireRecentMfa(c: Context<Env>, p: Principal, hasFactors: boolean) {
  if (!hasFactors) return;
  if (p.mfaAt && Date.now() - p.mfaAt.getTime() < STEP_UP_WINDOW_MS) return;
  c.header("WWW-Authenticate", 'Bearer error="insufficient_user_authentication", max_age=600');
  throw new ApiError(401, "step_up_required", "Re-verify with MFA to perform this action");
}

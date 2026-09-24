import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import * as OTPAuth from "otpauth";
import type { App, Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { notifyUsers } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { permissionsFor } from "../rbac.js";
import { getSettings, mfaRequired } from "../org/settings.js";
import type { SessionState } from "../platform/db-types.js";
import {
  bearer,
  body,
  Factor,
  Id,
  iso,
  isoOrNull,
  json,
  Organization,
  Permission,
  problemResponses,
  Role as RoleSchema,
  Session,
  User,
  toUser,
} from "../schemas.js";
import { requireRecentMfa, requireSession } from "./guard.js";
import { hashPassword, MIN_PASSWORD_LENGTH, verifyPassword } from "./passwords.js";
import { RateLimiter } from "./ratelimit.js";
import { hashToken, newSessionToken } from "./tokens.js";

const loginLimiter = new RateLimiter(10, 5 * 60_000); // per email+IP
const mfaLimiter = new RateLimiter(5, 5 * 60_000); // per session

const Client = z.enum(["web", "mobile", "cli"]).default("web");
const SessionStateSchema = z.enum(["pending_mfa", "enroll_mfa", "active"]).openapi("SessionState");
const ENROLL_TTL_MS = 30 * 60 * 1000;
const Password = z.string().min(MIN_PASSWORD_LENGTH).max(256);

const AuthResult = z
  .object({
    token: z.string().openapi({ description: "Bearer token. Store securely; it is shown only once." }),
    session: z.object({ id: Id, state: SessionStateSchema, expires_at: z.string() }),
    mfa: z.object({
      required: z.boolean().openapi({ description: "A second factor must be verified before the session is usable" }),
      enrollment_required: z.boolean().openapi({ description: "The org policy requires setting up MFA before continuing" }),
      factors: z.array(z.enum(["totp", "push", "webauthn"])),
    }),
  })
  .openapi("AuthResult");

const Me = z
  .object({
    user: User,
    organization: Organization,
    roles: z.array(RoleSchema),
    permissions: z.array(Permission),
    session: z.object({ id: Id, state: SessionStateSchema, client: z.string(), mfa_at: z.string().nullable() }),
  })
  .openapi("Me");

// ---- helpers --------------------------------------------------------------------

function slugify(name: string) {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40) || "org"
  );
}

export async function loadUser(tx: Tx, userId: string) {
  return tx
    .selectFrom("users")
    .selectAll("users")
    .select((eb) => [
      eb
        .selectFrom("user_roles")
        .whereRef("user_roles.user_id", "=", "users.id")
        .select(sql<string[]>`coalesce(array_agg(role ORDER BY role), '{}')`.as("r"))
        .as("roles"),
      eb
        .exists(
          eb
            .selectFrom("auth_factors")
            .whereRef("auth_factors.user_id", "=", "users.id")
            .where("auth_factors.verified_at", "is not", null),
        )
        .as("mfa_enrolled"),
    ])
    .where("users.id", "=", userId)
    .executeTakeFirst();
}

export async function createSession(
  tx: Tx,
  deps: Deps,
  meta: RequestMeta,
  a: { orgId: string; userId: string; state: SessionState; client: string; activeTtlMs: number; mfa?: boolean },
) {
  const token = newSessionToken();
  const ttl = a.state === "active" ? a.activeTtlMs : a.state === "enroll_mfa" ? ENROLL_TTL_MS : deps.cfg.pendingMfaTtlMs;
  const session = {
    id: newId(),
    org_id: a.orgId,
    user_id: a.userId,
    token_hash: hashToken(token),
    state: a.state,
    client: a.client,
    ip: meta.ip,
    user_agent: meta.userAgent.slice(0, 512),
    mfa_at: a.mfa ? new Date() : null,
    last_seen_at: new Date(),
    expires_at: new Date(Date.now() + ttl),
  };
  await tx.insertInto("sessions").values(session).execute();
  return { token, session };
}

export const verifiedFactorTypes = async (tx: Tx, userId: string) =>
  (
    await tx
      .selectFrom("auth_factors")
      .select("type")
      .distinct()
      .where("user_id", "=", userId)
      .where("verified_at", "is not", null)
      .execute()
  ).map((f) => f.type);

/** Returns the matched 30-second time-step, or null. Callers reject steps at or before the last accepted one (replay). */
function totpStep(secretBase32: string, code: string): number | null {
  const totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secretBase32), digits: 6, period: 30 });
  const delta = totp.validate({ token: code, window: 1 });
  return delta === null ? null : Math.floor(Date.now() / 30_000) + delta;
}

/** Verifies a TOTP code against the user's verified factors; returns the matching factor ID. */
async function verifyUserTotp(tx: Tx, deps: Deps, userId: string, code: string) {
  const factors = await tx
    .selectFrom("auth_factors")
    .select(["id", "secret_sealed", "last_totp_step"])
    .where("user_id", "=", userId)
    .where("type", "=", "totp")
    .where("verified_at", "is not", null)
    .execute();
  for (const f of factors) {
    if (!f.secret_sealed) continue;
    const step = totpStep(deps.sealer.open(f.secret_sealed, f.id).toString("utf8"), code);
    if (step === null || (f.last_totp_step !== null && step <= f.last_totp_step)) continue;
    await tx.updateTable("auth_factors").set({ last_totp_step: step, last_used_at: new Date() }).where("id", "=", f.id).execute();
    return f.id;
  }
  return null;
}

/**
 * Proving possession of a factor counts as fresh MFA for this session. If the
 * session was waiting on mandatory enrollment, it becomes fully active.
 */
export async function markFreshMfa(tx: Tx, p: { orgId: string; sessionId: string; sessionState: SessionState }) {
  const now = new Date();
  if (p.sessionState === "enroll_mfa") {
    const settings = await getSettings(tx, p.orgId);
    await tx
      .updateTable("sessions")
      .set({ state: "active", mfa_at: now, expires_at: new Date(Date.now() + settings.session_ttl_hours * 3600_000) })
      .where("id", "=", p.sessionId)
      .execute();
  } else {
    await tx.updateTable("sessions").set({ mfa_at: now }).where("id", "=", p.sessionId).execute();
  }
}

// ---- routes ---------------------------------------------------------------------

export function registerAuthRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/signup",
      tags: ["Auth"],
      summary: "Create an organization and its owner account",
      request: body(
        z.object({
          organization_name: z.string().trim().min(2).max(100),
          email: z.email(),
          password: Password,
          given_name: z.string().trim().min(1).max(100),
          family_name: z.string().trim().max(100).default(""),
          client: Client,
        }),
      ),
      responses: { 201: json(AuthResult, "Created"), ...problemResponses },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const { db, cfg } = c.get("deps");
      const meta = c.get("meta");

      const { emailTaken, slug } = await db.unscoped(async (tx) => {
        const emailTaken = (await sql<{ t: boolean }>`SELECT nexus_email_taken(${input.email}) AS t`.execute(tx))
          .rows[0]!.t;
        let slug = slugify(input.organization_name);
        for (let i = 2; (await sql<{ t: boolean }>`SELECT nexus_org_slug_taken(${slug}) AS t`.execute(tx)).rows[0]!.t; i++) {
          slug = `${slugify(input.organization_name)}-${i}`;
        }
        return { emailTaken, slug };
      });
      if (emailTaken) throw conflict("email_taken", "An account with this email already exists");

      const orgId = newId();
      const userId = newId();
      const passwordHash = await hashPassword(input.password);

      const result = await db.tenant(orgId, async (tx) => {
        await tx
          .insertInto("organizations")
          .values({ id: orgId, name: input.organization_name, slug, settings: JSON.stringify({}) })
          .execute();
        await tx
          .insertInto("users")
          .values({
            id: userId,
            org_id: orgId,
            email: input.email.toLowerCase(),
            given_name: input.given_name,
            family_name: input.family_name,
            password_hash: passwordHash,
            attributes: JSON.stringify({}),
            last_login_at: new Date(),
            updated_at: new Date(),
          })
          .execute();
        await tx.insertInto("user_roles").values({ org_id: orgId, user_id: userId, role: "owner" }).execute();
        const s = await createSession(tx, c.get("deps"), meta, { orgId, userId, state: "active", client: input.client, activeTtlMs: 12 * 3600_000 });

        const who = { meta, display: input.email };
        const actor = { type: "user" as const, id: userId, display: input.email };
        await audit(tx, orgId, who, { type: "org.created", actor, sessionId: s.session.id, target: { type: "organization", id: orgId, display: input.organization_name } });
        await audit(tx, orgId, who, { type: "user.created", actor, sessionId: s.session.id, target: { type: "user", id: userId, display: input.email }, details: { roles: ["owner"] } });
        await notifyUsers(tx, orgId, [userId], {
          category: "system.welcome",
          title: "Welcome to Nexus",
          body: "Start by protecting your own account: set up multi-factor authentication.",
          link: "/settings/security",
        });
        return s;
      });

      return c.json(
        {
          token: result.token,
          session: { id: result.session.id, state: "active" as const, expires_at: iso(result.session.expires_at) },
          mfa: { required: false, enrollment_required: false, factors: [] },
        },
        201,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/login",
      tags: ["Auth"],
      summary: "Sign in with email and password",
      description:
        "Returns an active session, or a `pending_mfa` session when the user has MFA enrolled. A pending session can only call the `/v1/auth/mfa/*` endpoints.",
      request: body(z.object({ email: z.email(), password: z.string().min(1).max(256), client: Client })),
      responses: { 200: json(AuthResult), ...problemResponses, 429: { description: "Too many attempts" } },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const meta = c.get("meta");
      const email = input.email.toLowerCase();

      if (!loginLimiter.take(`${email}|${meta.ip}`)) {
        throw new ApiError(429, "rate_limited", "Too many sign-in attempts. Try again in a few minutes.");
      }

      const found = await deps.db.unscoped(async (tx) => {
        const r = await sql<{ user_id: string; org_id: string; password_hash: string | null; status: string }>`
          SELECT * FROM nexus_auth_find_user(${email})`.execute(tx);
        return r.rows[0];
      });
      const ok = await verifyPassword(found?.password_hash ?? null, input.password);
      const invalid = new ApiError(401, "invalid_credentials", "Incorrect email or password");

      if (!found) throw invalid;
      const who = { meta, display: email };
      const actor = { type: "user" as const, id: found.user_id, display: email };

      if (!ok) {
        await deps.db.tenant(found.org_id, (tx) =>
          audit(tx, found.org_id, who, { type: "auth.login", outcome: "failure", actor, details: { reason: "bad_password", client: input.client } }),
        );
        throw invalid;
      }
      if (found.status !== "active") {
        await deps.db.tenant(found.org_id, (tx) =>
          audit(tx, found.org_id, who, { type: "auth.login", outcome: "denied", actor, details: { reason: `user_${found.status}` } }),
        );
        throw found.status === "staged"
          ? new ApiError(403, "invitation_pending", "Accept your invitation email to finish setting up your account.")
          : new ApiError(403, "account_inactive", "This account is not active. Contact your administrator.");
      }

      const result = await deps.db.tenant(found.org_id, async (tx) => {
        const factors = await verifiedFactorTypes(tx, found.user_id);
        const settings = await getSettings(tx, found.org_id);
        const isAdmin = !!(await tx.selectFrom("user_roles").select("role").where("user_id", "=", found.user_id).executeTakeFirst());
        const state: SessionState =
          factors.length > 0 ? "pending_mfa" : mfaRequired(settings, isAdmin) ? "enroll_mfa" : "active";
        const s = await createSession(tx, deps, meta, {
          orgId: found.org_id,
          userId: found.user_id,
          state,
          client: input.client,
          activeTtlMs: settings.session_ttl_hours * 3600_000,
        });
        if (state === "active") {
          await tx.updateTable("users").set({ last_login_at: new Date() }).where("id", "=", found.user_id).execute();
        }
        await audit(tx, found.org_id, who, {
          type: "auth.login",
          actor,
          sessionId: s.session.id,
          details: { client: input.client, mfa: { pending_mfa: "pending", enroll_mfa: "enrollment_required", active: "not_enrolled" }[state] },
        });
        return { ...s, factors };
      });

      return c.json(
        {
          token: result.token,
          session: { id: result.session.id, state: result.session.state, expires_at: iso(result.session.expires_at) },
          mfa: {
            required: result.session.state === "pending_mfa",
            enrollment_required: result.session.state === "enroll_mfa",
            factors: result.factors,
          },
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/mfa/totp",
      tags: ["Auth"],
      summary: "Complete sign-in (or step up) with a TOTP code",
      security: bearer,
      request: body(z.object({ code: z.string().regex(/^\d{6}$/) })),
      responses: { 200: json(z.object({ session: z.object({ id: Id, state: z.literal("active"), expires_at: z.string() }) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true });
      const deps = c.get("deps");
      const meta = c.get("meta");
      if (!mfaLimiter.take(p.sessionId)) throw new ApiError(429, "rate_limited", "Too many attempts");
      const { code } = c.req.valid("json");

      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const factorId = await verifyUserTotp(tx, deps, p.userId, code);
        if (!factorId) {
          await audit(tx, p.orgId, { principal: p, meta }, { type: "auth.mfa", outcome: "failure", details: { factor: "totp" } });
          return null;
        }
        const now = new Date();
        const settings = await getSettings(tx, p.orgId);
        const expires = p.sessionState === "pending_mfa" ? new Date(Date.now() + settings.session_ttl_hours * 3600_000) : undefined;
        const s = await tx
          .updateTable("sessions")
          .set({ state: "active", mfa_at: now, ...(expires ? { expires_at: expires } : {}) })
          .where("id", "=", p.sessionId)
          .returning(["id", "expires_at"])
          .executeTakeFirstOrThrow();
        if (p.sessionState === "pending_mfa") {
          await tx.updateTable("users").set({ last_login_at: now }).where("id", "=", p.userId).execute();
        }
        await audit(tx, p.orgId, { principal: p, meta }, {
          type: p.sessionState === "pending_mfa" ? "auth.mfa" : "auth.step_up",
          details: { factor: "totp" },
        });
        return s;
      });
      // Commit the failure audit, then reject.
      if (!out) throw new ApiError(401, "invalid_code", "That code didn't work. Check your authenticator app and try again.");
      return c.json({ session: { id: out.id, state: "active" as const, expires_at: iso(out.expires_at) } }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/logout",
      tags: ["Auth"],
      summary: "Revoke the current session",
      security: bearer,
      responses: { 204: { description: "Signed out" }, ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true, allowEnroll: true });
      const { db } = c.get("deps");
      await db.tenant(p.orgId, async (tx) => {
        await tx.updateTable("sessions").set({ revoked_at: new Date() }).where("id", "=", p.sessionId).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "auth.logout" });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/auth/session",
      tags: ["Auth"],
      summary: "The current session's sign-in state (works mid sign-in)",
      description: "Lets a client resume a sign-in: `pending_mfa` → verify a factor, `enroll_mfa` → set one up, `active` → done.",
      security: bearer,
      responses: {
        200: json(
          z
            .object({
              state: SessionStateSchema,
              email: z.string(),
              organization_name: z.string(),
              factors: z.array(z.enum(["totp", "push", "webauthn"])),
            })
            .openapi("SessionInfo"),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true, allowEnroll: true });
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => ({
        org: await tx.selectFrom("organizations").select("name").where("id", "=", p.orgId).executeTakeFirstOrThrow(),
        factors: await verifiedFactorTypes(tx, p.userId),
      }));
      return c.json({ state: p.sessionState, email: p.email, organization_name: out.org.name, factors: out.factors }, 200);
    },
  );

  // ---- /v1/me ---------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me",
      tags: ["Me"],
      summary: "The signed-in user, their organization, roles and effective permissions",
      description: "Clients use `permissions` to decide which actions to show. The server enforces them regardless.",
      security: bearer,
      responses: { 200: json(Me), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { db } = c.get("deps");
      const { user, org } = await db.tenant(p.orgId, async (tx) => ({
        user: await loadUser(tx, p.userId),
        org: await tx.selectFrom("organizations").selectAll().where("id", "=", p.orgId).executeTakeFirstOrThrow(),
      }));
      if (!user) throw notFound("User");
      return c.json(
        {
          user: toUser(user),
          organization: { id: org.id, name: org.name, slug: org.slug, created_at: iso(org.created_at) },
          roles: p.roles,
          permissions: permissionsFor(p.roles),
          session: { id: p.sessionId, state: p.sessionState, client: p.client, mfa_at: isoOrNull(p.mfaAt) },
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/factors",
      tags: ["Me"],
      summary: "List my MFA factors",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(Factor) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowEnroll: true });
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx.selectFrom("auth_factors").selectAll().where("user_id", "=", p.userId).orderBy("id").execute(),
      );
      return c.json(
        {
          data: rows.map((f) => ({
            id: f.id,
            type: f.type,
            name: f.name,
            verified: f.verified_at !== null,
            last_used_at: isoOrNull(f.last_used_at),
            created_at: iso(f.created_at),
          })),
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/factors/totp",
      tags: ["Me"],
      summary: "Start TOTP enrollment",
      description: "Returns a secret and `otpauth://` URL to show as a QR code. The factor is inactive until verified.",
      security: bearer,
      request: body(z.object({ name: z.string().trim().max(64).default("Authenticator app") })),
      responses: {
        201: json(z.object({ id: Id, secret: z.string(), otpauth_url: z.string() }).openapi("TotpEnrollment"), "Created"),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requireSession(c, { allowEnroll: true });
      const deps = c.get("deps");
      const { name } = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const [user, org] = await Promise.all([
          tx.selectFrom("users").select("email").where("id", "=", p.userId).executeTakeFirstOrThrow(),
          tx.selectFrom("organizations").select("name").where("id", "=", p.orgId).executeTakeFirstOrThrow(),
        ]);
        // Drop abandoned, never-verified enrollments.
        await tx.deleteFrom("auth_factors").where("user_id", "=", p.userId).where("type", "=", "totp").where("verified_at", "is", null).execute();
        const secret = new OTPAuth.Secret({ size: 20 });
        const id = newId();
        await tx
          .insertInto("auth_factors")
          .values({
            id,
            org_id: p.orgId,
            user_id: p.userId,
            type: "totp",
            name,
            secret_sealed: deps.sealer.seal(Buffer.from(secret.base32), id),
            public_key: null,
          })
          .execute();
        const totp = new OTPAuth.TOTP({ issuer: `Nexus (${org.name})`, label: user.email, secret, digits: 6, period: 30 });
        return { id, secret: secret.base32, otpauth_url: totp.toString() };
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/factors/{id}/verify",
      tags: ["Me"],
      summary: "Activate a TOTP factor by confirming a code",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ code: z.string().regex(/^\d{6}$/) })) },
      responses: { 200: json(Factor), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowEnroll: true });
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const { code } = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const f = await tx.selectFrom("auth_factors").selectAll().where("id", "=", id).where("user_id", "=", p.userId).executeTakeFirst();
        if (!f || f.type !== "totp" || !f.secret_sealed) throw notFound("Factor");
        if (f.verified_at) throw conflict("already_verified", "This factor is already active");
        const step = totpStep(deps.sealer.open(f.secret_sealed, f.id).toString("utf8"), code);
        if (step === null) {
          throw badRequest("invalid_code", "That code didn't match. Make sure your device clock is correct and try again.");
        }
        const now = new Date();
        const row = await tx
          .updateTable("auth_factors")
          .set({ verified_at: now, last_used_at: now, last_totp_step: step })
          .where("id", "=", id)
          .returningAll()
          .executeTakeFirstOrThrow();
        await markFreshMfa(tx, p);
        const meta = c.get("meta");
        await audit(tx, p.orgId, { principal: p, meta }, { type: "user.mfa_enrolled", target: { type: "user", id: p.userId }, details: { factor: "totp", factor_id: id } });
        await notifyUsers(tx, p.orgId, [p.userId], {
          category: "security.account",
          title: "Authenticator app added",
          body: `A new authenticator was added to your account from ${meta.ip || "an unknown IP"}. If this wasn't you, contact your administrator.`,
          link: "/settings/security",
        });
        return row;
      });
      return c.json(
        { id: out.id, type: out.type, name: out.name, verified: true, last_used_at: isoOrNull(out.last_used_at), created_at: iso(out.created_at) },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/me/factors/{id}",
      tags: ["Me"],
      summary: "Remove one of my MFA factors (requires recent MFA)",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 204: { description: "Removed" }, ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const meta = c.get("meta");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const factors = await verifiedFactorTypes(tx, p.userId);
        requireRecentMfa(c, p, factors.length > 0);
        const del = await tx.deleteFrom("auth_factors").where("id", "=", id).where("user_id", "=", p.userId).returning("type").executeTakeFirst();
        if (!del) throw notFound("Factor");
        await audit(tx, p.orgId, { principal: p, meta }, { type: "user.mfa_removed", target: { type: "user", id: p.userId }, details: { factor: del.type, factor_id: id } });
        await notifyUsers(tx, p.orgId, [p.userId], {
          category: "security.account",
          severity: "warning",
          title: "An MFA method was removed from your account",
          link: "/settings/security",
        });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/sessions",
      tags: ["Me"],
      summary: "List my active sessions across web, mobile and CLI",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(Session) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx
          .selectFrom("sessions")
          .selectAll()
          .where("user_id", "=", p.userId)
          .where("revoked_at", "is", null)
          .where("expires_at", ">", new Date())
          .orderBy("last_seen_at", "desc")
          .execute(),
      );
      return c.json({ data: rows.map((s) => sessionOut(s, p.sessionId)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/me/sessions/{id}",
      tags: ["Me"],
      summary: "Sign out one of my sessions",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 204: { description: "Revoked" }, ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx
          .updateTable("sessions")
          .set({ revoked_at: new Date() })
          .where("id", "=", id)
          .where("user_id", "=", p.userId)
          .where("revoked_at", "is", null)
          .executeTakeFirst();
        if (r.numUpdatedRows === 0n) throw notFound("Session");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "session.revoked", target: { type: "session", id } });
      });
      return c.body(null, 204);
    },
  );
}

export function sessionOut(
  s: { id: string; state: SessionState; client: string; ip: string; user_agent: string; mfa_at: Date | null; created_at: Date; last_seen_at: Date; expires_at: Date },
  currentId?: string,
) {
  return {
    id: s.id,
    state: s.state,
    client: s.client,
    ip: s.ip,
    user_agent: s.user_agent,
    current: s.id === currentId,
    mfa_at: isoOrNull(s.mfa_at),
    created_at: iso(s.created_at),
    last_seen_at: iso(s.last_seen_at),
    expires_at: iso(s.expires_at),
  };
}


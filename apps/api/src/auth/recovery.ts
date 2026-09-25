import { createRoute, z } from "@hono/zod-openapi";
import { createHash, randomBytes, randomInt } from "node:crypto";
import { sql } from "kysely";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { revokeUserSessions } from "../directory/users.js";
import { notifyRoles, notifyUsers } from "../notify/send.js";
import { breachCount } from "../platform/breach.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, conflict } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { layout } from "../platform/mailer.js";
import { bearer, body, iso, json, problemResponses } from "../schemas.js";
import { requireRecentMfa, requireSession } from "./guard.js";
import { hashPassword, MIN_PASSWORD_LENGTH, verifyPassword } from "./passwords.js";
import { RateLimiter } from "./ratelimit.js";
import { getSettings } from "../org/settings.js";
import { verifiedFactorTypes } from "./routes.js";
import { directoryPasswordCheck } from "../directory/sync/ldap.js";
import { federationRequiredFor } from "../federation/enforce.js";
import { hashToken } from "./tokens.js";

/**
 * Account recovery (AUTH-01/02/08): recovery codes, self-service password
 * reset, password change, breached-password checks and "I lost every MFA
 * method" requests. A reset never bypasses MFA: it only sets a password.
 */

const Password = z.string().min(MIN_PASSWORD_LENGTH).max(256);

/** Refuses passwords known from breaches. Fails open if the checking service is down. */
export async function assertNotBreached(deps: Deps, password: string) {
  const n = await breachCount(deps.cfg.hibpBase, password);
  if (n && n > 0) {
    throw badRequest("breached_password", `This password has appeared in ${n.toLocaleString()} known data breaches. Choose a different one.`, {
      errors: [{ path: "password", message: "Found in known data breaches" }],
    });
  }
}

// ---- recovery codes -------------------------------------------------------------------

const ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"; // no 0/o, 1/l/i
const CODE_COUNT = 10;
const codeHash = (code: string) => createHash("sha256").update(code.toLowerCase().replace(/[^a-z0-9]/g, "")).digest();
const newCode = () => {
  const c = Array.from({ length: 10 }, () => ALPHABET[randomInt(ALPHABET.length)]).join("");
  return `${c.slice(0, 5)}-${c.slice(5)}`;
};

export async function recoveryCodesLeft(tx: Tx, userId: string) {
  const r = await tx.selectFrom("recovery_codes").select((eb) => eb.fn.countAll<number>().as("n")).where("user_id", "=", userId).where("used_at", "is", null).executeTakeFirstOrThrow();
  return Number(r.n);
}

// ---- limits ---------------------------------------------------------------------------

const codeLimiter = new RateLimiter(5, 5 * 60_000); // recovery code attempts per session
const resetLimiter = new RateLimiter(3, 60 * 60_000); // reset emails per address per hour
const resetIpLimiter = new RateLimiter(20, 60 * 60_000); // …and per IP
const helpLimiter = new RateLimiter(1, 60 * 60_000); // "I lost my factors" per user per hour
const RESET_TTL_MS = 30 * 60_000;

async function passwordChangedEmail(deps: Deps, email: string, how: string) {
  const { html, text } = layout({
    heading: "Your Nexus password was changed",
    body: `Your password was ${how}. You've been signed out everywhere. If this wasn't you, contact your IT team right away.`,
    cta: { label: "Sign in", url: `${deps.cfg.publicUrl}/login` },
    footer: `Changed at ${new Date().toUTCString()}.`,
  });
  await deps.mailer.send({ to: email, subject: "Your Nexus password was changed", html, text });
}

export function registerRecoveryRoutes(app: App) {
  // Recovery codes ----------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/recovery-codes",
      tags: ["Me"],
      summary: "How many unused recovery codes you have",
      security: bearer,
      responses: { 200: json(z.object({ remaining: z.number().int(), created_at: z.string().nullable() })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const latest = await tx.selectFrom("recovery_codes").select("created_at").where("user_id", "=", p.userId).orderBy("created_at", "desc").executeTakeFirst();
        return { remaining: await recoveryCodesLeft(tx, p.userId), created_at: latest ? iso(latest.created_at) : null };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/recovery-codes",
      tags: ["Me"],
      summary: "Generate new recovery codes (replaces the old ones; requires recent MFA)",
      description: "Returned once. Each code signs you in once when you can't use your other methods.",
      security: bearer,
      responses: { 201: json(z.object({ codes: z.array(z.string()) }), "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const codes = Array.from({ length: CODE_COUNT }, newCode);
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const factors = await verifiedFactorTypes(tx, p.userId);
        if (!factors.length) throw badRequest("no_factor", "Set up an MFA method first; recovery codes back it up");
        requireRecentMfa(c, p, true, { personal: true });
        await tx.deleteFrom("recovery_codes").where("user_id", "=", p.userId).execute();
        await tx.insertInto("recovery_codes").values(codes.map((code) => ({ id: newId(), org_id: p.orgId, user_id: p.userId, code_hash: codeHash(code) }))).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "auth.recovery_codes_generated", target: { type: "user", id: p.userId, display: p.email } });
      });
      return c.json({ codes }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/mfa/recovery-code",
      tags: ["Auth"],
      summary: "Complete sign-in (or step up) with a recovery code",
      security: bearer,
      request: body(z.object({ code: z.string().min(10).max(20) })),
      responses: { 200: json(z.object({ remaining: z.number().int() })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true });
      if (!codeLimiter.take(p.sessionId)) throw new ApiError(429, "rate_limited", "Too many attempts");
      const deps = c.get("deps");
      const meta = c.get("meta");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const used = await tx
          .updateTable("recovery_codes")
          .set({ used_at: new Date() })
          .where("user_id", "=", p.userId)
          .where("code_hash", "=", codeHash(c.req.valid("json").code))
          .where("used_at", "is", null)
          .returning("id")
          .executeTakeFirst();
        if (!used) {
          await audit(tx, p.orgId, { principal: p, meta }, { type: "auth.mfa", outcome: "failure", details: { factor: "recovery_code" } });
          return null;
        }
        const settings = await getSettings(tx, p.orgId);
        const now = new Date();
        await tx
          .updateTable("sessions")
          .set({ state: "active", mfa_at: now, mfa_method: "recovery_code", ...(p.sessionState === "pending_mfa" ? { expires_at: new Date(Date.now() + settings.session_ttl_hours * 3600_000) } : {}) })
          .where("id", "=", p.sessionId)
          .execute();
        if (p.sessionState === "pending_mfa") await tx.updateTable("users").set({ last_login_at: now }).where("id", "=", p.userId).execute();
        const remaining = await recoveryCodesLeft(tx, p.userId);
        await audit(tx, p.orgId, { principal: p, meta }, { type: p.sessionState === "pending_mfa" ? "auth.mfa" : "auth.step_up", details: { factor: "recovery_code", remaining } });
        if (remaining <= 2) {
          await notifyUsers(tx, p.orgId, [p.userId], {
            category: "security.account",
            severity: "warning",
            title: remaining ? `Only ${remaining} recovery code${remaining === 1 ? "" : "s"} left` : "You've used your last recovery code",
            body: "Generate new recovery codes in My security, and check your usual MFA methods still work.",
            link: "/settings/security",
          });
        }
        return { remaining };
      });
      if (!out) throw new ApiError(401, "invalid_code", "That recovery code didn't work, or was already used.");
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/mfa/help",
      tags: ["Auth"],
      summary: "Ask an admin for help when you can't use any MFA method",
      security: bearer,
      responses: { 202: { description: "Admins were notified" }, ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true });
      if (!helpLimiter.take(p.userId)) return c.body(null, 202); // already asked recently
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "auth.mfa_help_requested", target: { type: "user", id: p.userId, display: p.email } });
        await notifyRoles(tx, p.orgId, ["owner", "admin", "helpdesk"], {
          category: "security.account",
          severity: "warning",
          title: `${p.email} can't use any MFA method`,
          body: `They signed in with their password and asked for help. Verify it's really them (for example on a video call), then reset their MFA so they can set it up again. The request came from ${c.get("meta").ip || "an unknown IP"}.`,
          entity: { type: "user", id: p.userId },
          link: `/users/${p.userId}`,
        });
      });
      return c.body(null, 202);
    },
  );

  // Password reset ----------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/password-reset",
      tags: ["Auth"],
      summary: "Email a password reset link",
      description: "Always answers 202, whether or not the email has an account.",
      request: body(z.object({ email: z.email() })),
      responses: { 202: { description: "If the account exists, a link was sent" }, ...problemResponses },
    }),
    async (c) => {
      const deps = c.get("deps");
      const meta = c.get("meta");
      const email = c.req.valid("json").email.toLowerCase();
      if (!resetLimiter.take(email) || !resetIpLimiter.take(meta.ip)) return c.body(null, 202);
      const found = await deps.db.unscoped(async (tx) => (await sql<{ user_id: string; org_id: string; status: string }>`SELECT * FROM nexus_auth_find_user(${email})`.execute(tx)).rows[0]);
      if (!found || found.status !== "active") return c.body(null, 202);
      if (await federationRequiredFor(deps, email, found)) return c.body(null, 202); // they sign in with their IdP; there's no Nexus password to reset
      if (await directoryPasswordCheck(deps, found.org_id, found.user_id)) return c.body(null, 202); // their password lives in the company directory
      const token = `nxr_${randomBytes(32).toString("base64url")}`;
      await deps.db.tenant(found.org_id, async (tx) => {
        await tx.updateTable("password_resets").set({ used_at: new Date() }).where("user_id", "=", found.user_id).where("used_at", "is", null).execute();
        await tx.insertInto("password_resets").values({ id: newId(), org_id: found.org_id, user_id: found.user_id, token_hash: hashToken(token), ip: meta.ip, expires_at: new Date(Date.now() + RESET_TTL_MS) }).execute();
        await audit(tx, found.org_id, { meta, display: email }, { type: "auth.password_reset_requested", actor: { type: "user", id: found.user_id, display: email }, target: { type: "user", id: found.user_id, display: email } });
      });
      const { html, text } = layout({
        heading: "Reset your Nexus password",
        body: `Someone (hopefully you) asked to reset the password for ${email}. You'll still need your usual MFA method to sign in afterwards.`,
        cta: { label: "Choose a new password", url: `${deps.cfg.publicUrl}/reset-password?token=${encodeURIComponent(token)}` },
        footer: `This link works once and expires in 30 minutes. If you didn't ask for it, ignore this email: your password hasn't changed.`,
      });
      await deps.mailer.send({ to: email, subject: "Reset your Nexus password", html, text }).catch(() => undefined);
      return c.body(null, 202);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/password-reset/complete",
      tags: ["Auth"],
      summary: "Set a new password with a reset link",
      description: "Signs you out everywhere. Sign in again afterwards; MFA still applies.",
      request: body(z.object({ token: z.string().max(200), password: Password })),
      responses: { 204: { description: "Password changed" }, ...problemResponses },
    }),
    async (c) => {
      const deps = c.get("deps");
      const meta = c.get("meta");
      const { token, password } = c.req.valid("json");
      const found = await deps.db.unscoped(async (tx) => (await sql<{ reset_id: string; org_id: string; user_id: string; email: string }>`SELECT * FROM nexus_password_reset_lookup(${hashToken(token)})`.execute(tx)).rows[0]);
      if (!found) throw new ApiError(404, "reset_invalid", "This reset link is invalid or has expired. Ask for a new one.");
      await assertNotBreached(deps, password);
      const passwordHash = await hashPassword(password);
      await deps.db.tenant(found.org_id, async (tx) => {
        const r = await tx.updateTable("password_resets").set({ used_at: new Date() }).where("id", "=", found.reset_id).where("used_at", "is", null).returning("id").executeTakeFirst();
        if (!r) throw new ApiError(404, "reset_invalid", "This reset link was already used.");
        await tx.updateTable("users").set({ password_hash: passwordHash, updated_at: new Date() }).where("id", "=", found.user_id).execute();
        const sessions = await revokeUserSessions(tx, found.user_id);
        await audit(tx, found.org_id, { meta, display: found.email }, {
          type: "user.password_reset",
          actor: { type: "user", id: found.user_id, display: found.email },
          target: { type: "user", id: found.user_id, display: found.email },
          details: { sessions_revoked: sessions },
        });
      });
      await passwordChangedEmail(deps, found.email, "reset with an emailed link").catch(() => undefined);
      return c.body(null, 204);
    },
  );

  // Password change ---------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/me/password",
      tags: ["Me"],
      summary: "Change your password (requires recent MFA)",
      description: "Signs out your other sessions.",
      security: bearer,
      request: body(z.object({ current_password: z.string().max(256), new_password: Password })),
      responses: { 204: { description: "Changed" }, ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const deps = c.get("deps");
      const { current_password, new_password } = c.req.valid("json");
      const directory = await directoryPasswordCheck(deps, p.orgId, p.userId);
      if (directory) throw conflict("directory_password", `Your password is managed in ${directory.connection}. Change it there (for example, Ctrl+Alt+Del on a Windows PC).`);
      const user = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0, { personal: true });
        return tx.selectFrom("users").select(["password_hash", "email"]).where("id", "=", p.userId).executeTakeFirstOrThrow();
      });
      if (!(await verifyPassword(user.password_hash, current_password))) {
        throw badRequest("wrong_password", "Your current password is incorrect", { errors: [{ path: "current_password", message: "Incorrect" }] });
      }
      if (current_password === new_password) throw badRequest("same_password", "Choose a password you haven't used here");
      await assertNotBreached(deps, new_password);
      const passwordHash = await hashPassword(new_password);
      await deps.db.tenant(p.orgId, async (tx) => {
        await tx.updateTable("users").set({ password_hash: passwordHash, updated_at: new Date() }).where("id", "=", p.userId).execute();
        const others = await tx.updateTable("sessions").set({ revoked_at: new Date() }).where("user_id", "=", p.userId).where("id", "<>", p.sessionId).where("revoked_at", "is", null).executeTakeFirst();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "user.password_changed", target: { type: "user", id: p.userId, display: p.email }, details: { other_sessions_revoked: Number(others.numUpdatedRows) } });
      });
      await passwordChangedEmail(deps, user.email, "changed from your account settings").catch(() => undefined);
      return c.body(null, 204);
    },
  );
}

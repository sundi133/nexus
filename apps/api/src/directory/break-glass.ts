import { createRoute, z } from "@hono/zod-openapi";
import { randomInt } from "node:crypto";
import type { App, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { hashPassword } from "../auth/passwords.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { notifyRoles } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { badRequest, notFound } from "../platform/errors.js";
import { bearer, body, Id, json, problemResponses } from "../schemas.js";
import { revokeUserSessions } from "./users.js";

/**
 * Break-glass accounts (RBAC-05): emergency owner accounts for when SSO,
 * the directory or everyone's MFA is broken. They're exempt from anything that
 * could lock the organization out (directory sync suspensions, conditional
 * access, offboarding), and every use raises a critical alert.
 */

/** Called on every successful sign-in step that proves the password or a passkey. */
export async function alertIfBreakGlass(tx: Tx, orgId: string, userId: string, meta: RequestMeta, method: string) {
  const u = await tx.selectFrom("users").select(["email", "break_glass"]).where("id", "=", userId).executeTakeFirst();
  if (!u?.break_glass) return;
  await audit(tx, orgId, { meta, display: u.email }, {
    type: "auth.break_glass_used",
    outcome: "success",
    actor: { type: "user", id: userId, display: u.email },
    target: { type: "user", id: userId, display: u.email },
    details: { method, ip: meta.ip, user_agent: meta.userAgent },
  });
  await notifyRoles(tx, orgId, ["owner", "admin", "security_analyst"], {
    category: "security.break_glass",
    severity: "critical",
    title: `Break-glass account ${u.email} was used`,
    body: `Signed in with ${method} from ${meta.ip || "an unknown IP"}. If this wasn't a planned emergency, contain the account now and rotate its credentials.`,
    entity: { type: "user", id: userId },
    link: `/users/${userId}`,
  });
}

// 6 groups of 5 from an unambiguous alphabet: ~150 bits, meant to be printed and sealed.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const emergencyPassword = () => Array.from({ length: 6 }, () => Array.from({ length: 5 }, () => ALPHABET[randomInt(ALPHABET.length)]).join("")).join("-");

export function registerBreakGlassRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/users/{id}/break-glass",
      tags: ["Users"],
      summary: "Designate (or stop designating) an owner as a break-glass account (owners only; requires recent MFA)",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ enabled: z.boolean() })) },
      responses: { 200: json(z.object({ break_glass: z.boolean() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "admins:manage");
      const { id } = c.req.valid("param");
      const { enabled } = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const u = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", id).executeTakeFirst();
        if (!u) throw notFound("User");
        const isOwner = !!(await tx.selectFrom("user_roles").select("role").where("user_id", "=", id).where("role", "=", "owner").executeTakeFirst());
        if (enabled && !isOwner) throw badRequest("not_owner", "A break-glass account must be an owner: make them an owner first");
        await tx.updateTable("users").set({ break_glass: enabled, updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: enabled ? "user.break_glass_designated" : "user.break_glass_removed", target: { type: "user", id, display: u.email } });
      });
      return c.json({ break_glass: enabled }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/users/{id}/break-glass/password",
      tags: ["Users"],
      summary: "Generate a sealed emergency password (owners only; requires recent MFA)",
      description: "Shown once, to print and seal. Replaces the account's password and signs it out everywhere.",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 201: json(z.object({ password: z.string() }), "Generated"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "admins:manage");
      const { id } = c.req.valid("param");
      const password = emergencyPassword();
      const hash = await hashPassword(password);
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const u = await tx.selectFrom("users").select(["email", "break_glass"]).where("id", "=", id).executeTakeFirst();
        if (!u) throw notFound("User");
        if (!u.break_glass) throw badRequest("not_break_glass", "Only break-glass accounts get a sealed emergency password");
        await tx.updateTable("users").set({ password_hash: hash, updated_at: new Date() }).where("id", "=", id).execute();
        const sessions = await revokeUserSessions(tx, id);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "user.break_glass_password_generated", target: { type: "user", id, display: u.email }, details: { sessions_revoked: sessions } });
      });
      return c.json({ password }, 201);
    },
  );
}

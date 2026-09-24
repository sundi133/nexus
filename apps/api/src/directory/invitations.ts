import { createRoute, z } from "@hono/zod-openapi";
import { randomBytes } from "node:crypto";
import { sql } from "kysely";
import type { App, Deps, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission } from "../auth/guard.js";
import { hashPassword, MIN_PASSWORD_LENGTH } from "../auth/passwords.js";
import { createSession, verifiedFactorTypes } from "../auth/routes.js";
import { hashToken } from "../auth/tokens.js";
import { notifyUsers } from "../notify/send.js";
import { getSettings, mfaRequired } from "../org/settings.js";
import type { Tx } from "../platform/db.js";
import { ApiError, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { layout } from "../platform/mailer.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import type { SessionState } from "../platform/db-types.js";

const INVITE_TTL_MS = 7 * 24 * 3600_000;

export type PendingInvite = { email: string; token: string; orgName: string; inviterName: string; expiresAt: Date };

/**
 * Creates (or re-issues) an invitation for a staged user inside the caller's
 * transaction. The email must be sent only after commit, via sendInvite().
 */
export async function issueInvitation(tx: Tx, p: Principal, userId: string): Promise<PendingInvite> {
  const user = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", userId).executeTakeFirst();
  if (!user) throw notFound("User");
  if (user.status !== "staged") throw conflict("not_staged", "Only users who haven't accepted an invitation can be invited");
  await tx.updateTable("invitations").set({ revoked_at: new Date() }).where("user_id", "=", userId).where("accepted_at", "is", null).execute();
  const token = `nxi_${randomBytes(32).toString("base64url")}`;
  const expiresAt = new Date(Date.now() + INVITE_TTL_MS);
  await tx
    .insertInto("invitations")
    .values({ id: newId(), org_id: p.orgId, user_id: userId, token_hash: hashToken(token), invited_by: p.userId, expires_at: expiresAt })
    .execute();
  const [org, inviter] = await Promise.all([
    tx.selectFrom("organizations").select("name").where("id", "=", p.orgId).executeTakeFirstOrThrow(),
    tx.selectFrom("users").select(["given_name", "family_name", "email"]).where("id", "=", p.userId).executeTakeFirstOrThrow(),
  ]);
  return {
    email: user.email,
    token,
    orgName: org.name,
    inviterName: `${inviter.given_name} ${inviter.family_name}`.trim() || inviter.email,
    expiresAt,
  };
}

export async function sendInvite(deps: Deps, inv: PendingInvite) {
  const url = `${deps.cfg.publicUrl}/invite?token=${encodeURIComponent(inv.token)}`;
  const { html, text } = layout({
    heading: `Join ${inv.orgName} on Nexus`,
    body: `${inv.inviterName} invited you to ${inv.orgName}. Nexus is how your team signs in to work apps securely. Set your password to get started.`,
    cta: { label: "Accept invitation", url },
    footer: `This link expires on ${inv.expiresAt.toUTCString()}. If you weren't expecting this, you can ignore it.`,
  });
  await deps.mailer.send({ to: inv.email, subject: `You're invited to ${inv.orgName}`, html, text });
}

type Lookup = { invitation_id: string; org_id: string; user_id: string; email: string; org_name: string; expires_at: Date };

async function lookup(deps: Deps, token: string) {
  const row = await deps.db.unscoped(async (tx) => {
    const r = await sql<Lookup>`SELECT * FROM nexus_invitation_lookup(${hashToken(token)})`.execute(tx);
    return r.rows[0];
  });
  if (!row) throw new ApiError(404, "invitation_invalid", "This invitation link is invalid or has expired. Ask your administrator to send a new one.");
  return row;
}

export function registerInvitationRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/users/{id}/invite",
      tags: ["Users"],
      summary: "Send (or re-send) an invitation email to a staged user",
      description: "Any earlier invitation link for this user stops working.",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ sent_to: z.string(), expires_at: z.string() }).openapi("InvitationSent")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:write");
      const { id } = c.req.valid("param");
      const deps = c.get("deps");
      const inv = await deps.db.tenant(p.orgId, async (tx) => {
        const inv = await issueInvitation(tx, p, id);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "user.invited", target: { type: "user", id, display: inv.email } });
        return inv;
      });
      await sendInvite(deps, inv);
      return c.json({ sent_to: inv.email, expires_at: iso(inv.expiresAt) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/invitations/{token}",
      tags: ["Invitations"],
      summary: "Look up an invitation (public; the token is the credential)",
      request: { params: z.object({ token: z.string().max(200) }) },
      responses: {
        200: json(z.object({ email: z.string(), organization_name: z.string(), expires_at: z.string() }).openapi("Invitation")),
        ...problemResponses,
      },
    }),
    async (c) => {
      const inv = await lookup(c.get("deps"), c.req.valid("param").token);
      return c.json({ email: inv.email, organization_name: inv.org_name, expires_at: iso(inv.expires_at) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/invitations/accept",
      tags: ["Invitations"],
      summary: "Accept an invitation: set a password and sign in",
      description: "If the organization requires MFA for this user, the returned session is `enroll_mfa` until they set up a factor.",
      request: body(
        z.object({
          token: z.string().max(200),
          password: z.string().min(MIN_PASSWORD_LENGTH).max(256),
          client: z.enum(["web", "mobile", "cli"]).default("web"),
        }),
      ),
      responses: {
        200: json(
          z
            .object({
              token: z.string(),
              session: z.object({ id: Id, state: z.enum(["pending_mfa", "enroll_mfa", "active"]), expires_at: z.string() }),
              mfa: z.object({ required: z.boolean(), enrollment_required: z.boolean(), factors: z.array(z.enum(["totp", "push", "webauthn"])) }),
            })
            .openapi("InvitationAccepted"),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const meta = c.get("meta");
      const inv = await lookup(deps, input.token);
      const passwordHash = await hashPassword(input.password);

      const out = await deps.db.tenant(inv.org_id, async (tx) => {
        // Consume the invitation atomically so a link can only be used once.
        const consumed = await tx
          .updateTable("invitations")
          .set({ accepted_at: new Date() })
          .where("id", "=", inv.invitation_id)
          .where("accepted_at", "is", null)
          .returning(["invited_by"])
          .executeTakeFirst();
        if (!consumed) throw new ApiError(404, "invitation_invalid", "This invitation has already been used.");
        await tx
          .updateTable("users")
          .set({ password_hash: passwordHash, status: "active", last_login_at: new Date(), updated_at: new Date() })
          .where("id", "=", inv.user_id)
          .execute();

        const settings = await getSettings(tx, inv.org_id);
        const isAdmin = !!(await tx.selectFrom("user_roles").select("role").where("user_id", "=", inv.user_id).executeTakeFirst());
        const factors = await verifiedFactorTypes(tx, inv.user_id);
        const state: SessionState = factors.length ? "pending_mfa" : mfaRequired(settings, isAdmin) ? "enroll_mfa" : "active";
        const s = await createSession(tx, deps, meta, {
          orgId: inv.org_id,
          userId: inv.user_id,
          state,
          client: input.client,
          activeTtlMs: settings.session_ttl_hours * 3600_000,
        });
        const actor = { type: "user" as const, id: inv.user_id, display: inv.email };
        await audit(tx, inv.org_id, { meta }, {
          type: "user.invitation_accepted",
          actor,
          sessionId: s.session.id,
          target: { type: "user", id: inv.user_id, display: inv.email },
        });
        if (consumed.invited_by) {
          await notifyUsers(tx, inv.org_id, [consumed.invited_by], {
            category: "directory.invite_accepted",
            title: `${inv.email} joined ${inv.org_name}`,
            entity: { type: "user", id: inv.user_id },
            link: `/users/${inv.user_id}`,
          });
        }
        return { ...s, factors };
      });

      return c.json(
        {
          token: out.token,
          session: { id: out.session.id, state: out.session.state, expires_at: iso(out.session.expires_at) },
          mfa: { required: out.session.state === "pending_mfa", enrollment_required: out.session.state === "enroll_mfa", factors: out.factors },
        },
        200,
      );
    },
  );
}

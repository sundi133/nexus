import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { requirePermission } from "../auth/guard.js";
import { auditQuery, toAuditEvent } from "../audit/routes.js";
import { AuditEvent, bearer, json, problemResponses } from "../schemas.js";
import { getSettings } from "../org/settings.js";

const Attention = z
  .object({
    id: z.string(),
    severity: z.enum(["critical", "warning", "info"]),
    title: z.string(),
    description: z.string(),
    count: z.number().int(),
    link: z.string(),
    action_label: z.string(),
  })
  .openapi("AttentionItem");

const Overview = z
  .object({
    stats: z.object({
      users_total: z.number().int(),
      users_active: z.number().int(),
      users_suspended: z.number().int(),
      admins: z.number().int(),
      groups: z.number().int(),
      mfa_coverage: z.number().openapi({ description: "Share of active users with MFA, 0..1" }),
      logins_24h: z.number().int(),
      failed_logins_24h: z.number().int(),
    }),
    needs_attention: z.array(Attention),
    recent_activity: z.array(AuditEvent),
  })
  .openapi("Overview");

type Counts = {
  users_total: number;
  users_active: number;
  users_suspended: number;
  active_without_mfa: number;
  admins: number;
  admins_without_mfa: number;
  owners: number;
  groups: number;
  logins_24h: number;
  failed_logins_24h: number;
};

export function registerOverviewRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/overview",
      tags: ["Overview"],
      summary: "Security posture summary and the ranked 'Needs attention' queue (SPEC OPS-02)",
      security: bearer,
      responses: { 200: json(Overview), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      const { counts, recent, settings, certs } = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await sql<Counts>`
          WITH u AS (
            SELECT users.id, users.status,
              EXISTS (SELECT 1 FROM auth_factors f WHERE f.user_id = users.id AND f.verified_at IS NOT NULL) AS mfa,
              EXISTS (SELECT 1 FROM user_roles r WHERE r.user_id = users.id) AS admin,
              EXISTS (SELECT 1 FROM user_roles r WHERE r.user_id = users.id AND r.role = 'owner') AS owner
            FROM users WHERE status <> 'deprovisioned'
          )
          SELECT
            count(*)::int                                                   AS users_total,
            count(*) FILTER (WHERE status = 'active')::int                  AS users_active,
            count(*) FILTER (WHERE status = 'suspended')::int               AS users_suspended,
            count(*) FILTER (WHERE status = 'active' AND NOT mfa)::int      AS active_without_mfa,
            count(*) FILTER (WHERE status = 'active' AND admin)::int        AS admins,
            count(*) FILTER (WHERE status = 'active' AND admin AND NOT mfa)::int AS admins_without_mfa,
            count(*) FILTER (WHERE status = 'active' AND owner)::int        AS owners,
            (SELECT count(*) FROM groups)::int                              AS groups,
            (SELECT count(*) FROM audit_events WHERE type = 'auth.login' AND outcome = 'success'
               AND ts > now() - interval '24 hours')::int                   AS logins_24h,
            (SELECT count(*) FROM audit_events WHERE type IN ('auth.login', 'auth.mfa') AND outcome <> 'success'
               AND ts > now() - interval '24 hours')::int                   AS failed_logins_24h
          FROM u`.execute(tx);
        const recent = await auditQuery(tx).orderBy("id", "desc").limit(8).execute();
        const certs = await tx
          .selectFrom("signing_keys")
          .select(["status", "not_after", "created_at"])
          .where("purpose", "=", "saml")
          .where("status", "in", ["active", "next"])
          .execute();
        return { counts: r.rows[0]!, recent, settings: await getSettings(tx, p.orgId), certs };
      });

      const items: z.infer<typeof Attention>[] = [];
      if (counts.admins_without_mfa > 0) {
        items.push({
          id: "admins_without_mfa",
          severity: "critical",
          title: `${counts.admins_without_mfa} admin${counts.admins_without_mfa > 1 ? "s" : ""} without MFA`,
          description: "Admin accounts are the highest-value target. Require MFA before anything else.",
          count: counts.admins_without_mfa,
          link: "/users?role=any_admin&mfa=missing",
          action_label: "Review admins",
        });
      }
      if (counts.active_without_mfa - counts.admins_without_mfa > 0) {
        const n = counts.active_without_mfa - counts.admins_without_mfa;
        items.push({
          id: "users_without_mfa",
          severity: "warning",
          title: `${n} user${n > 1 ? "s" : ""} without MFA`,
          description: "These accounts can be taken over with a stolen password alone.",
          count: n,
          link: "/users?mfa=missing",
          action_label: "View users",
        });
      }
      if (settings.mfa_policy !== "everyone") {
        items.push({
          id: "mfa_not_required",
          severity: "warning",
          title: settings.mfa_policy === "off" ? "MFA isn't required" : "MFA is only required for admins",
          description: "Apply the secure baseline to require MFA for everyone. You'll see exactly who is affected first.",
          count: 1,
          link: "/settings/organization",
          action_label: "Review baseline",
        });
      }
      const activeCert = certs.find((x) => x.status === "active");
      const nextCert = certs.find((x) => x.status === "next");
      const daysLeft = activeCert?.not_after ? Math.floor((activeCert.not_after.getTime() - Date.now()) / 86_400_000) : null;
      if (daysLeft !== null && daysLeft < 60 && !nextCert) {
        items.push({
          id: "saml_cert_expiring",
          severity: daysLeft < 14 ? "critical" : "warning",
          title: `SAML signing certificate expires in ${Math.max(daysLeft, 0)} days`,
          description: "Every SAML app stops accepting sign-ins when it expires. Start a rotation and update your apps.",
          count: 1,
          link: "/settings/organization#certificates",
          action_label: "Rotate certificate",
        });
      }
      if (nextCert && Date.now() - nextCert.created_at.getTime() > 14 * 86_400_000) {
        items.push({
          id: "saml_rotation_pending",
          severity: "info",
          title: "A SAML certificate rotation is still pending",
          description: "The next certificate was created over two weeks ago. Activate it once your apps trust it.",
          count: 1,
          link: "/settings/organization#certificates",
          action_label: "Finish rotation",
        });
      }
      if (counts.failed_logins_24h >= 5) {
        items.push({
          id: "failed_logins",
          severity: "warning",
          title: `${counts.failed_logins_24h} failed sign-ins in the last 24h`,
          description: "Could be typos, or a password-spraying attempt. Check the sources.",
          count: counts.failed_logins_24h,
          link: "/audit?type=auth.*&outcome=failure",
          action_label: "Investigate",
        });
      }
      if (counts.owners === 1) {
        items.push({
          id: "single_owner",
          severity: "info",
          title: "Only one owner",
          description: "Add a second owner so you can't be locked out of your organization.",
          count: 1,
          link: "/users?role=owner",
          action_label: "Manage owners",
        });
      }

      const { active_without_mfa, owners, admins_without_mfa, ...stats } = counts;
      return c.json(
        {
          stats: {
            ...stats,
            mfa_coverage: counts.users_active ? (counts.users_active - active_without_mfa) / counts.users_active : 1,
          },
          needs_attention: items,
          recent_activity: recent.map(toAuditEvent),
        },
        200,
      );
    },
  );
}

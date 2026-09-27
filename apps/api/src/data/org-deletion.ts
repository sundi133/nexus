import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa, requireSession } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { notifyRoles } from "../notify/send.js";
import type { JobRunner } from "../platform/jobs.js";
import { badRequest, conflict, forbidden } from "../platform/errors.js";
import { bearer, body, iso, json, problemResponses } from "../schemas.js";

/**
 * Deleting the organization (leaving Nexus). An owner schedules it; it happens after a grace
 * period (default 30 days) that any owner can cancel; then a worker deletes every tenant row
 * and emails a deletion certificate. Only the certificate remains (migration 0047).
 */

const graceDays = () => Math.max(1, Number(process.env.NEXUS_ORG_DELETION_GRACE_DAYS) || 30);

const DeletionStatus = z
  .object({
    scheduled_for: z.string().nullable().openapi({ description: "When everything will be deleted; null if no deletion is scheduled" }),
    requested_at: z.string().nullable(),
    requested_by: z.string().nullable().openapi({ description: "Who scheduled it (email)" }),
    reason: z.string().nullable(),
    grace_days: z.number().int(),
  })
  .openapi("OrgDeletionStatus");

const ScheduleInput = z
  .object({
    confirm_name: z.string().openapi({ description: "The organization's name, typed exactly" }),
    reason: z.string().trim().min(3).max(500),
  })
  .openapi("OrgDeletionInput");

async function status(deps: Deps, orgId: string) {
  return deps.db.tenant(orgId, async (tx) => {
    const o = await tx
      .selectFrom("organizations")
      .leftJoin("users", "users.id", "organizations.deletion_requested_by")
      .select(["organizations.deletion_scheduled_for", "organizations.deletion_requested_at", "organizations.deletion_reason", "users.email"])
      .where("organizations.id", "=", orgId)
      .executeTakeFirstOrThrow();
    return {
      scheduled_for: o.deletion_scheduled_for ? iso(o.deletion_scheduled_for) : null,
      requested_at: o.deletion_requested_at ? iso(o.deletion_requested_at) : null,
      requested_by: o.deletion_scheduled_for ? (o.email ?? null) : null,
      reason: o.deletion_reason,
      grace_days: graceDays(),
    };
  });
}

export function registerOrgDeletionRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/org/deletion",
      tags: ["Data"],
      summary: "Whether the organization is scheduled for deletion",
      security: bearer,
      responses: { 200: json(DeletionStatus), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      return c.json(await status(c.get("deps"), p.orgId), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/org/deletion",
      tags: ["Data"],
      summary: "Schedule the deletion of the organization and all its data",
      description:
        "Owners only, with a recent MFA (a passkey if the organization requires it for owners), never an API key. Everything is deleted after the grace period (default 30 days); until then the organization works as usual and any owner can cancel. Owners and admins are told now, and owners get a deletion certificate by email afterwards. Export your data first (`GET /v1/org/export`).",
      security: bearer,
      request: body(ScheduleInput),
      responses: { 200: json(DeletionStatus), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      if (!p.roles.includes("owner")) throw forbidden("Only an owner can delete the organization");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const o = await tx.selectFrom("organizations").select(["name", "deletion_scheduled_for"]).where("id", "=", p.orgId).forUpdate().executeTakeFirstOrThrow();
        if (input.confirm_name.trim() !== o.name) throw badRequest("confirmation_mismatch", "Type the organization's name exactly to confirm");
        if (o.deletion_scheduled_for) throw conflict("already_scheduled", "Deletion is already scheduled");
        const when = new Date(Date.now() + graceDays() * 86_400_000);
        await tx
          .updateTable("organizations")
          .set({ deletion_scheduled_for: when, deletion_requested_by: p.userId, deletion_requested_at: new Date(), deletion_reason: input.reason })
          .where("id", "=", p.orgId)
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "organization.deletion_scheduled", details: { scheduled_for: when.toISOString(), reason: input.reason } });
        await notifyRoles(tx, p.orgId, ["owner", "admin"], {
          category: "security.alert",
          severity: "critical",
          title: `${o.name} will be deleted on ${when.toISOString().slice(0, 10)}`,
          body: `${p.email} scheduled the deletion of the organization and all its data. Any owner can cancel it until then in Settings → Organization.`,
          link: "/settings/organization",
        });
      });
      return c.json(await status(deps, p.orgId), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/org/deletion",
      tags: ["Data"],
      summary: "Cancel a scheduled deletion",
      security: bearer,
      responses: { 200: json(DeletionStatus), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      if (!p.roles.includes("owner")) throw forbidden("Only an owner can cancel the deletion");
      const deps = c.get("deps");
      await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const o = await tx.selectFrom("organizations").select(["name", "deletion_scheduled_for"]).where("id", "=", p.orgId).forUpdate().executeTakeFirstOrThrow();
        if (!o.deletion_scheduled_for) throw conflict("not_scheduled", "No deletion is scheduled");
        await tx
          .updateTable("organizations")
          .set({ deletion_scheduled_for: null, deletion_requested_by: null, deletion_requested_at: null, deletion_reason: null })
          .where("id", "=", p.orgId)
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "organization.deletion_cancelled", details: {} });
        await notifyRoles(tx, p.orgId, ["owner", "admin"], {
          category: "security.alert",
          severity: "warning",
          title: `The deletion of ${o.name} was cancelled`,
          body: `${p.email} cancelled it. Nothing will be deleted.`,
          link: "/settings/organization",
        });
      });
      return c.json(await status(deps, p.orgId), 200);
    },
  );
}

type Certificate = { organization_id: string; name: string; deleted_at: string; requested_at: string | null; row_counts: Record<string, number>; notify: string[] };

/** Deletes organizations whose grace period is over, and emails each one's certificate. */
export async function deleteDueOrganizations(deps: Deps) {
  const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_orgs_due_for_deletion()`.execute(tx)).rows);
  const done: Certificate[] = [];
  for (const { org_id } of due) {
    const cert = await deps.db.unscoped(async (tx) => (await sql<{ c: Certificate | null }>`SELECT nexus_delete_organization(${org_id}::uuid) AS c`.execute(tx)).rows[0]!.c);
    if (!cert) continue; // cancelled meanwhile
    done.push(cert);
    console.log(JSON.stringify({ level: "info", msg: "organization deleted", organization_id: cert.organization_id, rows: Object.values(cert.row_counts).reduce((a, b) => a + b, 0) }));
    const counts = Object.entries(cert.row_counts).map(([t, n]) => `  ${t}: ${n}`).join("\n");
    const text = `The Votal Nexus organization "${cert.name}" (${cert.organization_id}) and all its data were deleted on ${cert.deleted_at}${cert.requested_at ? `, as requested on ${cert.requested_at}` : ""}.\n\nRows deleted, by table:\n${counts}\n\nEncrypted database backups age out on their own schedule (see the operator's retention policy). Keep this email as your record.`;
    const html = `<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Inter,sans-serif;color:#0f1115"><pre style="white-space:pre-wrap;font:14px/1.5 inherit">${text.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`)}</pre></body></html>`;
    for (const to of cert.notify) {
      await deps.mailer
        .send({ to, subject: `Deletion certificate: ${cert.name}`, text, html })
        .catch((e) => console.error(`[org-deletion] certificate email to ${to} failed:`, e));
    }
  }
  return done;
}

export function scheduleOrgDeletions(jobs: JobRunner, deps: Deps) {
  jobs.every("organizations.delete", 5 * 60_000, async () => void (await deleteDueOrganizations(deps)));
}

import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import type { App, Env, Principal, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { notifyRoles } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { badRequest, conflict, forbidden, notFound } from "../platform/errors.js";
import { enqueue, registerJobHandler } from "../platform/jobs.js";
import { can } from "../rbac.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { touchGroups, touchUsers } from "../provisioning/service.js";
import { revokeUserSessions } from "./users.js";

/**
 * One-click offboarding (DIR-06): everything a leaver's access consists of,
 * removed in one audited transaction, now or on their last day. Final: the
 * account is deprovisioned and can't be reactivated.
 */

const Preview = z
  .object({
    user: z.object({ id: Id, email: z.string(), display_name: z.string(), status: z.string(), managed_by_directory: z.boolean() }),
    sessions: z.number().int(),
    admin_roles: z.array(z.string()),
    groups: z.array(z.object({ id: Id, name: z.string() })),
    apps: z.array(z.object({ id: Id, name: z.string(), provisioned: z.boolean(), action: z.enum(["deactivate", "delete", "sign_in_only"]) })),
    devices: z.array(z.object({ id: Id, hostname: z.string() })),
    factors: z.number().int(),
    scheduled: z.object({ at: z.string(), reason: z.string() }).nullable(),
  })
  .openapi("OffboardingPreview");

const dedupe = (userId: string) => `user.offboard:${userId}`;

async function preview(tx: Tx, userId: string): Promise<z.infer<typeof Preview>> {
  const u = await tx.selectFrom("users").select(["id", "email", "given_name", "family_name", "status"]).where("id", "=", userId).executeTakeFirst();
  if (!u) throw notFound("User");
  const groups = await tx.selectFrom("group_members").innerJoin("groups", "groups.id", "group_members.group_id").select(["groups.id", "groups.name"]).where("group_members.user_id", "=", userId).orderBy("groups.name").execute();
  const groupIds = groups.map((g) => g.id);
  const apps = await tx
    .selectFrom("applications")
    .leftJoin("app_provisioning", "app_provisioning.app_id", "applications.id")
    .leftJoin("provisioned_accounts", (j) => j.onRef("provisioned_accounts.app_id", "=", "applications.id").on("provisioned_accounts.user_id", "=", userId))
    .select(["applications.id", "applications.name", "app_provisioning.enabled", "app_provisioning.on_unassign", "provisioned_accounts.state"])
    .where((eb) =>
      eb.or([
        eb.exists(eb.selectFrom("app_assignments").whereRef("app_assignments.app_id", "=", "applications.id").where("principal_type", "=", "user").where("principal_id", "=", userId)),
        ...(groupIds.length ? [eb.exists(eb.selectFrom("app_assignments").whereRef("app_assignments.app_id", "=", "applications.id").where("principal_type", "=", "group").where("principal_id", "in", groupIds))] : []),
        eb("provisioned_accounts.state", "in", ["active", "error"]),
      ]),
    )
    .orderBy("applications.name")
    .execute();
  const sessions = await tx.selectFrom("sessions").select((eb) => eb.fn.countAll<number>().as("n")).where("user_id", "=", userId).where("revoked_at", "is", null).where("expires_at", ">", new Date()).executeTakeFirstOrThrow();
  const factors = await tx.selectFrom("auth_factors").select((eb) => eb.fn.countAll<number>().as("n")).where("user_id", "=", userId).executeTakeFirstOrThrow();
  const roles = await tx.selectFrom("user_roles").select("role").where("user_id", "=", userId).execute();
  const devices = await tx.selectFrom("devices").select(["id", "hostname"]).where("primary_user_id", "=", userId).where("status", "=", "active").execute();
  const job = await tx.selectFrom("jobs").select(["run_at", "payload"]).where("kind", "=", "user.offboard").where("dedupe_key", "=", dedupe(userId)).where("status", "=", "queued").executeTakeFirst();
  const managed = await tx.selectFrom("directory_links").select("local_id").where("kind", "=", "user").where("local_id", "=", userId).executeTakeFirst();
  return {
    user: { id: u.id, email: u.email, display_name: `${u.given_name} ${u.family_name}`.trim() || u.email, status: u.status, managed_by_directory: !!managed },
    sessions: Number(sessions.n),
    admin_roles: roles.map((r) => r.role),
    groups,
    apps: apps.map((a) => ({
      id: a.id,
      name: a.name,
      provisioned: !!a.enabled && !!a.state,
      action: a.enabled && a.state ? (a.on_unassign === "delete" ? ("delete" as const) : ("deactivate" as const)) : ("sign_in_only" as const),
    })),
    devices,
    factors: Number(factors.n),
    scheduled: job ? { at: iso(job.run_at), reason: String((job.payload as unknown as { reason?: string }).reason ?? "") } : null,
  };
}

/** Does it. Shared by the immediate action and the scheduled job. */
export async function offboard(tx: Tx, orgId: string, userId: string, who: { principal?: Principal; meta: RequestMeta }, reason: string) {
  const before = await preview(tx, userId);
  if (before.user.status === "deprovisioned") return { already: true as const, before };
  await tx.updateTable("users").set({ status: "deprovisioned", updated_at: new Date() }).where("id", "=", userId).execute();
  const sessions = await revokeUserSessions(tx, userId);
  await tx.deleteFrom("user_roles").where("user_id", "=", userId).execute();
  await tx.deleteFrom("group_members").where("user_id", "=", userId).execute();
  await tx.deleteFrom("app_assignments").where("principal_type", "=", "user").where("principal_id", "=", userId).execute();
  const factors = await tx.deleteFrom("auth_factors").where("user_id", "=", userId).executeTakeFirst();
  await tx.deleteFrom("push_registrations").where("user_id", "=", userId).execute();
  await tx.updateTable("invitations").set({ revoked_at: new Date() }).where("user_id", "=", userId).where("accepted_at", "is", null).where("revoked_at", "is", null).execute();
  await tx.updateTable("devices").set({ primary_user_id: null, updated_at: new Date() }).where("primary_user_id", "=", userId).execute();
  await tx.deleteFrom("jobs").where("kind", "=", "user.offboard").where("dedupe_key", "=", dedupe(userId)).where("status", "=", "queued").execute();
  // App accounts: the provisioning engine sees "deprovisioned" and deactivates (or deletes) them everywhere.
  await touchUsers(tx, orgId, [userId]);
  await touchGroups(tx, orgId, before.groups.map((g) => g.id));

  const effects = {
    sessions_revoked: sessions,
    admin_roles_removed: before.admin_roles,
    groups_removed: before.groups.map((g) => g.name),
    app_accounts: before.apps.filter((a) => a.provisioned).map((a) => `${a.name}: ${a.action}`),
    sign_in_only_apps: before.apps.filter((a) => !a.provisioned).map((a) => a.name),
    factors_removed: Number(factors.numDeletedRows),
    devices_unassigned: before.devices.map((d) => d.hostname),
  };
  await audit(tx, orgId, who, {
    type: "user.offboarded",
    ...(who.principal ? {} : { actor: { type: "system" as const, id: null, display: "Scheduled offboarding" } }),
    target: { type: "user", id: userId, display: before.user.email },
    details: { reason, effects },
  });
  if (before.devices.length) {
    await notifyRoles(tx, orgId, ["owner", "admin", "helpdesk"], {
      category: "directory.offboarding",
      severity: "info",
      title: `Collect ${before.devices.length === 1 ? before.devices[0]!.hostname : `${before.devices.length} devices`} from ${before.user.display_name}`,
      body: `${before.user.display_name} was offboarded. Their device${before.devices.length === 1 ? " is" : "s are"} now unassigned: ${before.devices.map((d) => d.hostname).join(", ")}.`,
      entity: { type: "user", id: userId },
      link: `/devices`,
    });
  }
  return { already: false as const, before, effects };
}

registerJobHandler("user.offboard", async (deps, job) => {
  const p = job.payload as { user_id: string; reason?: string };
  await deps.db.tenant(job.org_id, (tx) => offboard(tx, job.org_id, p.user_id, { meta: { ip: "", userAgent: "nexus-scheduler", requestId: job.id } }, p.reason ?? ""));
});

async function guard(c: Context<Env>, tx: Tx, p: Principal, userId: string) {
  if (userId === p.userId) throw badRequest("cannot_target_self", "You can't offboard yourself");
  const roles = (await tx.selectFrom("user_roles").select("role").where("user_id", "=", userId).execute()).map((r) => r.role);
  if (roles.includes("owner")) {
    if (!can(p.roles, "admins:manage")) throw forbidden("Only owners can offboard another owner");
    const owners = await tx
      .selectFrom("user_roles")
      .innerJoin("users", "users.id", "user_roles.user_id")
      .where("role", "=", "owner")
      .where("users.status", "=", "active")
      .select((eb) => eb.fn.countAll<number>().as("n"))
      .executeTakeFirstOrThrow();
    if (Number(owners.n) <= 1) throw conflict("last_owner", "The organization must keep at least one active owner");
  }
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

export function registerOffboardingRoutes(app: App) {
  const idParam = { params: z.object({ id: Id }) };

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/users/{id}/offboarding",
      tags: ["Users"],
      summary: "What offboarding this person would remove (and any scheduled offboarding)",
      security: bearer,
      request: idParam,
      responses: { 200: json(Preview), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:lifecycle");
      return c.json(await c.get("deps").db.tenant(p.orgId, (tx) => preview(tx, c.req.valid("param").id)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/users/{id}/offboard",
      tags: ["Users"],
      summary: "Offboard now, or on a date (requires recent MFA)",
      description:
        "Deprovisions the account (final), signs out everywhere, removes admin roles, groups, direct app assignments, MFA factors and pending invitations, unassigns devices, and deactivates accounts in every provisioned app. With `at` in the future it's scheduled instead.",
      security: bearer,
      request: { ...idParam, ...body(z.object({ reason: z.string().trim().max(500).default(""), at: z.iso.datetime().optional() })) },
      responses: { 200: json(Preview), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:lifecycle");
      const { id } = c.req.valid("param");
      const { reason, at } = c.req.valid("json");
      const meta = c.get("meta");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await guard(c, tx, p, id);
        const when = at ? new Date(at) : null;
        if (when && when.getTime() > Date.now() + 60_000) {
          const u = await preview(tx, id);
          if (u.user.status === "deprovisioned") throw conflict("already_offboarded", "This person is already offboarded");
          await tx.deleteFrom("jobs").where("kind", "=", "user.offboard").where("dedupe_key", "=", dedupe(id)).where("status", "=", "queued").execute();
          await enqueue(tx, p.orgId, "user.offboard", { user_id: id, reason }, { runAt: when, dedupeKey: dedupe(id), maxAttempts: 5 });
          await audit(tx, p.orgId, { principal: p, meta }, { type: "user.offboarding_scheduled", target: { type: "user", id, display: u.user.email }, details: { at: when.toISOString(), reason } });
        } else {
          const r = await offboard(tx, p.orgId, id, { principal: p, meta }, reason);
          if (r.already) throw conflict("already_offboarded", "This person is already offboarded");
        }
        return preview(tx, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/users/{id}/offboarding", tags: ["Users"], summary: "Cancel a scheduled offboarding", security: bearer, request: idParam, responses: { 200: json(Preview), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "users:lifecycle");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.deleteFrom("jobs").where("kind", "=", "user.offboard").where("dedupe_key", "=", dedupe(id)).where("status", "=", "queued").returning("id").executeTakeFirst();
        if (!r) throw notFound("Scheduled offboarding");
        const u = await preview(tx, id);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "user.offboarding_cancelled", target: { type: "user", id, display: u.user.email } });
        return u;
      });
      return c.json(out, 200);
    },
  );
}

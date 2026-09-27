import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { assertUserInScope, principalCan, requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, conflict, forbidden, notFound } from "../platform/errors.js";
import { bearer, body, Id, json, problemResponses } from "../schemas.js";
import { exportColumns, selectKept, SKIP_TABLES } from "./columns.js";

/**
 * Privacy requests about one person (GDPR/CCPA access and erasure): everything Nexus holds about
 * them, and deleting it. The audit log is the exception: it's append-only and hash-chained, kept
 * for security and legal obligations (GDPR Art. 17(3)(b), (e)), and ages out with audit retention.
 */

type Ref = { table: string; column: string; cascade: boolean };
let refs: Ref[] | null = null;

/** Every column that points at a person (from the schema's foreign keys), found once per process. */
async function personRefs(tx: Tx): Promise<Ref[]> {
  if (refs) return refs;
  const rows = (
    await sql<{ tbl: string; col: string; del: string }>`
      SELECT c.conrelid::regclass::text AS tbl, a.attname AS col, c.confdeltype::text AS del
      FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
      WHERE c.contype = 'f' AND c.confrelid = 'users'::regclass ORDER BY 1, 2`.execute(tx)
  ).rows;
  // Direct reports are other people's records, not this person's.
  refs = rows.filter((r) => !(r.tbl === "users" && r.col === "manager_id")).map((r) => ({ table: r.tbl, column: r.col, cascade: r.del === "c" }));
  return refs;
}

const MAX_AUDIT = 50_000;

async function personExport(tx: Tx, userId: string) {
  const data: Record<string, Record<string, unknown>[]> = {};
  const omitted: Record<string, string[]> = {};
  const take = async (table: string, where: ReturnType<typeof sql>) => {
    const cols = await exportColumns(tx, table);
    const rows = (await selectKept(table, cols, where).execute(tx)).rows;
    if (rows.length) data[table] = [...(data[table] ?? []), ...rows];
    if (cols.dropped.length) omitted[table] = cols.dropped;
  };
  await take("users", sql`id = ${userId}`);
  for (const r of await personRefs(tx)) {
    if (SKIP_TABLES.has(r.table)) continue;
    await take(r.table, sql`${sql.id(r.column)} = ${userId}`);
  }
  await take("directory_links", sql`kind = 'user' AND local_id = ${userId}`);
  const audit = (
    await sql<Record<string, unknown>>`
      SELECT id, ts, type, outcome, actor_type, actor_id, actor_display, target_type, target_id, target_display, ip, user_agent, details
      FROM audit_events WHERE actor_id = ${userId} OR (target_type = 'user' AND target_id = ${userId})
      ORDER BY ts LIMIT ${MAX_AUDIT + 1}`.execute(tx)
  ).rows;
  return { data, audit_events: audit.slice(0, MAX_AUDIT), audit_truncated: audit.length > MAX_AUDIT, omitted };
}

const PersonExport = z
  .object({
    format: z.literal("nexus-person-export/1"),
    exported_at: z.string(),
    user_id: z.string(),
    data: z.record(z.string(), z.array(z.record(z.string(), z.unknown()))).openapi({ description: "Rows by table: the profile, memberships, roles, factors (no secrets), sessions, devices, requests…" }),
    audit_events: z.array(z.record(z.string(), z.unknown())).openapi({ description: "Audit events where the person is the actor or the target (up to 50,000)" }),
    audit_truncated: z.boolean(),
    omitted: z.record(z.string(), z.array(z.string())).openapi({ description: "Columns left out as secrets (password hashes, sealed keys, token hashes)" }),
  })
  .openapi("PersonExport");

const EraseInput = z
  .object({
    confirm: z.string().openapi({ description: "The person's email address, typed to confirm" }),
    reason: z.string().trim().min(3).max(500).openapi({ example: "Erasure request under GDPR Art. 17, ticket PRIV-1042" }),
  })
  .openapi("EraseInput");

const EraseResult = z
  .object({
    erased: z.literal(true),
    removed: z.record(z.string(), z.number()).openapi({ description: "Rows deleted, by table" }),
    detached: z.record(z.string(), z.number()).openapi({ description: "Records kept (they belong to the organization) with the person removed from them, by table and column" }),
    directory_managed: z.boolean().openapi({ description: "True if a directory sync created them: remove them from the directory too, or the next sync adds them again" }),
  })
  .openapi("EraseResult");

export function registerPersonDataRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/users/{id}/data-export",
      tags: ["Data"],
      summary: "Everything Nexus holds about one person (privacy access request)",
      description: "Profile, group and role memberships, MFA factors and sessions (metadata only, never secrets), devices, requests and reviews, notifications, and audit events about them. Recorded in the audit log.",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(PersonExport), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read", { scoped: true });
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        await assertUserInScope(tx, p, "users:read", id);
        const u = await tx.selectFrom("users").select("email").where("id", "=", id).executeTakeFirst();
        if (!u) throw notFound("User");
        const e = await personExport(tx, id);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "user.data_exported", target: { type: "user", id, display: u.email }, details: { tables: Object.keys(e.data).length, audit_events: e.audit_events.length } });
        return e;
      });
      c.header("Content-Disposition", `attachment; filename="person-${id}.json"`);
      return c.json({ format: "nexus-person-export/1" as const, exported_at: new Date().toISOString(), user_id: id, ...out }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/users/{id}/erase",
      tags: ["Data"],
      summary: "Permanently delete a person and their personal data (privacy erasure request)",
      description:
        "Irreversible. The person must be suspended or offboarded first, so their access everywhere is gone, and their accounts in provisioned apps must be deactivated. Their profile, memberships, roles, factors, sessions, devices' assignment, requests and notifications are deleted; records that belong to the organization (policies they created, decisions they made) are kept without them. Audit events stay: the log is append-only and ages out with audit retention.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(EraseInput) },
      responses: { 200: json(EraseResult), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:erase", { scoped: true });
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        await assertUserInScope(tx, p, "users:erase", id);
        const u = await tx.selectFrom("users").select(["id", "email", "status", "break_glass"]).where("id", "=", id).forUpdate().executeTakeFirst();
        if (!u) throw notFound("User");
        if (u.id === p.userId) throw badRequest("cannot_target_self", "You can't erase your own account");
        if (input.confirm.trim().toLowerCase() !== u.email.toLowerCase()) throw badRequest("confirmation_mismatch", "Type the person's email address to confirm");
        if (u.break_glass) throw conflict("break_glass", "This is a break-glass account: remove that first");
        if (u.status === "active" || u.status === "staged") throw conflict("still_active", "Suspend or offboard them first, so their access everywhere is removed");
        const roles = (await tx.selectFrom("user_roles").select("role").where("user_id", "=", id).execute()).map((r) => r.role);
        if (roles.includes("owner") && !principalCan(p, "admins:manage")) throw forbidden("Only an owner can erase an owner");
        const live = await tx.selectFrom("provisioned_accounts").select((eb) => eb.fn.countAll<number>().as("n")).where("user_id", "=", id).where("state", "=", "active").executeTakeFirstOrThrow();
        if (Number(live.n) > 0) throw new ApiError(409, "provisioned_accounts_active", `${live.n} account(s) in provisioned apps are still active: wait for deprovisioning to finish, or retry it from the person's Apps tab`);

        const removed: Record<string, number> = {};
        const detached: Record<string, number> = {};
        for (const r of await personRefs(tx)) {
          const n = Number((await sql<{ n: number }>`SELECT count(*)::int AS n FROM ${sql.id(r.table)} WHERE ${sql.id(r.column)} = ${id}`.execute(tx)).rows[0]!.n);
          if (n) (r.cascade ? removed : detached)[r.cascade ? r.table : `${r.table}.${r.column}`] = n;
        }
        const links = await tx.deleteFrom("directory_links").where("kind", "=", "user").where("local_id", "=", id).executeTakeFirst();
        await tx.deleteFrom("users").where("id", "=", id).execute(); // cascades and SET NULLs through the foreign keys
        removed.users = 1;
        // The audit record names the person only by ID: erasure shouldn't write their email again.
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "user.erased", target: { type: "user", id, display: "erased person" }, details: { reason: input.reason, removed, detached } });
        return { removed, detached, directory_managed: Number(links.numDeletedRows) > 0 };
      });
      return c.json({ erased: true as const, ...out }, 200);
    },
  );
}

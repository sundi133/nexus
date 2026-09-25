import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { sql } from "kysely";
import type { App, Deps, Env, Principal, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa, requireSession } from "../auth/guard.js";
import { notifyUsers } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { badRequest, conflict, forbidden, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { enqueue, registerJobHandler, type JobRunner } from "../platform/jobs.js";
import { touchGroups, touchUsers } from "../provisioning/service.js";
import { can } from "../rbac.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { endGrant, type CatalogRow } from "./requests.js";

/**
 * Access reviews (JIT-05): a campaign snapshots who has an app, a group or an
 * admin role; reviewers keep or revoke each; closing (by an admin, or at the
 * due date) applies it. Nobody reviews their own access, break-glass accounts
 * are left out, and the last owner is never removed.
 */

type Review = { id: string; org_id: string; name: string; scope_type: "app" | "group" | "admin_roles"; scope_id: string | null; reviewer_kind: "users" | "manager"; reviewer_ids: string[]; on_no_decision: "keep" | "revoke"; status: string; due_at: Date; created_by: string | null };
type Outcome = "" | "kept" | "revoked" | "already_gone" | "skipped";
type Item = { id: string; user_id: string; grant_kind: "app_user" | "group_member" | "role"; grant_ref: string; via: string; reviewer_id: string | null; decision: "keep" | "revoke" | null; outcome: Outcome };

const SYSTEM: RequestMeta = { ip: "", userAgent: "nexus-access-reviews", requestId: "" };

async function scopeName(tx: Tx, r: Pick<Review, "scope_type" | "scope_id">) {
  if (r.scope_type === "admin_roles") return "admin roles";
  if (r.scope_type === "app") return (await tx.selectFrom("applications").select("name").where("id", "=", r.scope_id!).executeTakeFirst())?.name ?? "a removed app";
  return (await tx.selectFrom("groups").select("name").where("id", "=", r.scope_id!).executeTakeFirst())?.name ?? "a removed group";
}

/** Who has the access right now (break-glass and deprovisioned accounts excluded). */
async function snapshot(tx: Tx, r: Pick<Review, "scope_type" | "scope_id">): Promise<{ user_id: string; grant_kind: Item["grant_kind"]; grant_ref: string; via: string }[]> {
  const eligible = (q: { user_id: string }[]) => q;
  const people = async (ids: string[]) =>
    new Set(ids.length ? (await tx.selectFrom("users").select("id").where("id", "in", ids).where("break_glass", "=", false).where("status", "<>", "deprovisioned").execute()).map((u) => u.id) : []);
  if (r.scope_type === "app") {
    const direct = await tx.selectFrom("app_assignments").select("principal_id as user_id").where("app_id", "=", r.scope_id!).where("principal_type", "=", "user").execute();
    const viaGroups = await tx
      .selectFrom("app_assignments")
      .innerJoin("group_members", "group_members.group_id", "app_assignments.principal_id")
      .innerJoin("groups", "groups.id", "group_members.group_id")
      .select(["group_members.user_id", "groups.id as group_id", "groups.name"])
      .where("app_assignments.app_id", "=", r.scope_id!)
      .where("app_assignments.principal_type", "=", "group")
      .execute();
    const ok = await people([...direct.map((d) => d.user_id), ...viaGroups.map((g) => g.user_id)]);
    return [
      ...eligible(direct).filter((d) => ok.has(d.user_id)).map((d) => ({ user_id: d.user_id, grant_kind: "app_user" as const, grant_ref: r.scope_id!, via: "" })),
      ...viaGroups.filter((g) => ok.has(g.user_id)).map((g) => ({ user_id: g.user_id, grant_kind: "group_member" as const, grant_ref: g.group_id, via: `via group ${g.name}` })),
    ];
  }
  if (r.scope_type === "group") {
    const members = await tx.selectFrom("group_members").select("user_id").where("group_id", "=", r.scope_id!).execute();
    const ok = await people(members.map((m) => m.user_id));
    return members.filter((m) => ok.has(m.user_id)).map((m) => ({ user_id: m.user_id, grant_kind: "group_member" as const, grant_ref: r.scope_id!, via: "" }));
  }
  const roles = await tx.selectFrom("user_roles").select(["user_id", "role"]).execute();
  const ok = await people(roles.map((x) => x.user_id));
  return roles.filter((x) => ok.has(x.user_id)).map((x) => ({ user_id: x.user_id, grant_kind: "role" as const, grant_ref: x.role, via: "" }));
}

/** Can this person decide this item? Reviewers (or access admins), never for their own access. */
function canDecide(p: Principal, r: Review, i: Item) {
  if (r.status !== "open" || i.user_id === p.userId) return false;
  if (i.reviewer_id) return i.reviewer_id === p.userId || can(p.roles, "access:manage");
  return r.reviewer_ids.includes(p.userId) || can(p.roles, "access:manage");
}

async function revokeOne(tx: Tx, orgId: string, i: Item, meta: RequestMeta, reviewId: string): Promise<Outcome> {
  // Granted by an access request? End it there, so the request's history stays right.
  const kind = i.grant_kind === "app_user" ? "app" : i.grant_kind === "group_member" ? "group" : "role";
  const req = await tx
    .selectFrom("access_requests")
    .innerJoin("access_catalog", "access_catalog.id", "access_requests.catalog_id")
    .selectAll("access_requests")
    .select(["access_catalog.resource_type", "access_catalog.resource_id", "access_catalog.role", "access_catalog.max_hours", "access_catalog.allow_permanent", "access_catalog.stages", "access_catalog.eligible", "access_catalog.enabled"])
    .where("access_requests.requester_id", "=", i.user_id)
    .where("access_requests.status", "=", "active")
    .where("access_catalog.resource_type", "=", kind)
    .where(kind === "role" ? "access_catalog.role" : "access_catalog.resource_id", "=", i.grant_ref)
    .executeTakeFirst();
  if (req) {
    const cat: CatalogRow = { id: req.catalog_id, org_id: orgId, resource_type: req.resource_type, resource_id: req.resource_id, role: req.role, max_hours: req.max_hours, allow_permanent: req.allow_permanent, stages: req.stages, eligible: req.eligible, enabled: req.enabled };
    await endGrant(tx, cat, req, meta, { status: "revoked", reason: `Revoked in an access review` });
    return "revoked";
  }
  if (i.grant_kind === "app_user") {
    const r = await tx.deleteFrom("app_assignments").where("app_id", "=", i.grant_ref).where("principal_type", "=", "user").where("principal_id", "=", i.user_id).executeTakeFirst();
    if (!Number(r.numDeletedRows)) return "already_gone";
    await touchUsers(tx, orgId, [i.user_id], [i.grant_ref]);
  } else if (i.grant_kind === "group_member") {
    const r = await tx.deleteFrom("group_members").where("group_id", "=", i.grant_ref).where("user_id", "=", i.user_id).executeTakeFirst();
    if (!Number(r.numDeletedRows)) return "already_gone";
    await touchUsers(tx, orgId, [i.user_id]);
    await touchGroups(tx, orgId, [i.grant_ref]);
  } else {
    if (i.grant_ref === "owner") {
      const owners = await tx.selectFrom("user_roles").innerJoin("users", "users.id", "user_roles.user_id").select("user_roles.user_id").where("role", "=", "owner").where("users.status", "=", "active").execute();
      if (owners.length <= 1) return "skipped"; // the organization keeps at least one owner
    }
    const r = await tx.deleteFrom("user_roles").where("user_id", "=", i.user_id).where("role", "=", i.grant_ref).executeTakeFirst();
    if (!Number(r.numDeletedRows)) return "already_gone";
  }
  const email = (await tx.selectFrom("users").select("email").where("id", "=", i.user_id).executeTakeFirst())?.email ?? "";
  await audit(tx, orgId, { meta }, {
    type: "access.review_revoked",
    actor: { type: "system", id: null, display: "Access review" },
    target: { type: "user", id: i.user_id, display: email },
    details: { review_id: reviewId, item_id: i.id, grant: { kind: i.grant_kind, ref: i.grant_ref, via: i.via } },
  });
  return "revoked";
}

/** Applies every decision (and the default for undecided ones), then closes the review. */
export async function closeReview(tx: Tx, orgId: string, reviewId: string, meta: RequestMeta, by: { id: string; email: string } | null) {
  const r = (await tx.selectFrom("access_reviews").selectAll().where("id", "=", reviewId).forUpdate().executeTakeFirst()) as Review | undefined;
  if (!r) throw notFound("Access review");
  if (r.status !== "open") throw conflict("closed", "This review is already closed");
  const items = (await tx.selectFrom("access_review_items").selectAll().where("review_id", "=", reviewId).execute()) as Item[];
  const counts = { kept: 0, revoked: 0, already_gone: 0, skipped: 0, undecided: 0 };
  for (const i of items) {
    if (!i.decision) counts.undecided++;
    const final = i.decision ?? r.on_no_decision;
    const outcome: Outcome = final === "keep" ? "kept" : await revokeOne(tx, orgId, i, meta, reviewId);
    counts[outcome as keyof typeof counts]++;
    await tx.updateTable("access_review_items").set({ outcome }).where("id", "=", i.id).execute();
  }
  const summary = { ...counts, total: items.length };
  await tx.updateTable("access_reviews").set({ status: "closed", closed_at: new Date(), summary: JSON.stringify(summary) }).where("id", "=", reviewId).execute();
  await audit(tx, orgId, { meta }, {
    type: "access.review_closed",
    actor: by ? { type: "user", id: by.id, display: by.email } : { type: "system", id: null, display: "Access reviews (due date)" },
    target: { type: "access_review", id: reviewId, display: r.name },
    details: summary,
  });
  if (r.created_by) {
    await notifyUsers(tx, orgId, [r.created_by], {
      category: "access.review",
      title: `Access review “${r.name}” closed`,
      body: `${summary.kept} kept, ${summary.revoked} revoked${summary.undecided ? `, ${summary.undecided} undecided (${r.on_no_decision === "keep" ? "kept" : "revoked"})` : ""}.`,
      entity: { type: "access_review", id: reviewId },
      link: `/access-reviews/${reviewId}`,
    });
  }
  return summary;
}

registerJobHandler("access.review_close", async (deps, job) => {
  await deps.db.tenant(job.org_id, async (tx) => {
    const id = String((job.payload as { review_id: string }).review_id);
    const r = await tx.selectFrom("access_reviews").select(["status", "due_at"]).where("id", "=", id).executeTakeFirst();
    if (r?.status === "open" && r.due_at <= new Date()) await closeReview(tx, job.org_id, id, { ...SYSTEM, requestId: job.id }, null);
  });
});

registerJobHandler("access.review_remind", async (deps, job) => {
  await deps.db.tenant(job.org_id, async (tx) => {
    const id = String((job.payload as { review_id: string }).review_id);
    const r = (await tx.selectFrom("access_reviews").selectAll().where("id", "=", id).where("status", "=", "open").where("reminded_at", "is", null).executeTakeFirst()) as Review | undefined;
    if (!r) return;
    await tx.updateTable("access_reviews").set({ reminded_at: new Date() }).where("id", "=", id).execute();
    const pending = await tx.selectFrom("access_review_items").select(["reviewer_id", "user_id"]).where("review_id", "=", id).where("decision", "is", null).execute();
    const reviewers = new Set<string>();
    for (const i of pending) {
      if (i.reviewer_id) reviewers.add(i.reviewer_id);
      else for (const x of r.reviewer_ids) if (x !== i.user_id) reviewers.add(x);
    }
    if (!reviewers.size) return;
    await notifyUsers(tx, job.org_id, [...reviewers], {
      category: "access.review",
      severity: "warning",
      title: `Access review “${r.name}” is due tomorrow`,
      body: `${pending.length} ${pending.length === 1 ? "decision is" : "decisions are"} still open. Undecided access is ${r.on_no_decision === "keep" ? "kept" : "revoked"} when it closes.`,
      entity: { type: "access_review", id },
      link: `/access-reviews/${id}`,
    });
  });
});

export function scheduleAccessReviews(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 5 * 60_000) return;
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; review_id: string; action: string }>`SELECT * FROM nexus_access_reviews_due()`.execute(tx)).rows);
    for (const d of due) {
      const kind = d.action === "close" ? "access.review_close" : "access.review_remind";
      await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, kind, { review_id: d.review_id }, { dedupeKey: `${kind}:${d.review_id}` }));
    }
  });
}

// ---- API -------------------------------------------------------------------------------

const ReviewOut = z
  .object({
    id: Id,
    name: z.string(),
    scope: z.object({ type: z.enum(["app", "group", "admin_roles"]), id: Id.nullable(), name: z.string() }),
    reviewers: z.object({ kind: z.enum(["users", "manager"]), ids: z.array(Id) }),
    on_no_decision: z.enum(["keep", "revoke"]),
    status: z.enum(["open", "closed"]),
    due_at: z.string(),
    closed_at: z.string().nullable(),
    progress: z.object({ total: z.number().int(), decided: z.number().int(), yours_to_decide: z.number().int() }),
    summary: z.record(z.string(), z.number()),
    created_at: z.string(),
  })
  .openapi("AccessReview");
const ItemOut = z
  .object({
    id: Id,
    user: z.object({ id: Id, email: z.string(), name: z.string(), title: z.string(), department: z.string(), last_login_at: z.string().nullable() }),
    access: z.string().openapi({ description: "What they have, e.g. “admin role” or “via group Finance”" }),
    reviewer: z.string().nullable(),
    decision: z.enum(["keep", "revoke"]).nullable(),
    note: z.string(),
    decided_by: z.string().nullable(),
    decided_at: z.string().nullable(),
    outcome: z.string(),
    you_can_decide: z.boolean(),
  })
  .openapi("AccessReviewItem");

async function reviewOut(tx: Tx, p: Principal, r: Review & { closed_at: Date | null; summary: unknown; created_at: Date }): Promise<z.infer<typeof ReviewOut>> {
  const items = (await tx.selectFrom("access_review_items").selectAll().where("review_id", "=", r.id).execute()) as Item[];
  return {
    id: r.id,
    name: r.name,
    scope: { type: r.scope_type, id: r.scope_id, name: await scopeName(tx, r) },
    reviewers: { kind: r.reviewer_kind, ids: r.reviewer_ids },
    on_no_decision: r.on_no_decision,
    status: r.status as "open" | "closed",
    due_at: iso(r.due_at),
    closed_at: isoOrNull(r.closed_at),
    progress: { total: items.length, decided: items.filter((i) => i.decision).length, yours_to_decide: items.filter((i) => !i.decision && canDecide(p, r, i)).length },
    summary: r.summary as Record<string, number>,
    created_at: iso(r.created_at),
  };
}

async function itemsOut(tx: Tx, p: Principal, r: Review, mine: boolean): Promise<z.infer<typeof ItemOut>[]> {
  const rows = await tx
    .selectFrom("access_review_items as i")
    .innerJoin("users as u", "u.id", "i.user_id")
    .leftJoin("users as rv", "rv.id", "i.reviewer_id")
    .leftJoin("users as db", "db.id", "i.decided_by")
    .selectAll("i")
    .select(["u.email", "u.given_name", "u.family_name", "u.title", "u.department", "u.last_login_at", "rv.email as reviewer_email", "db.email as decided_by_email"])
    .where("i.review_id", "=", r.id)
    .orderBy("u.email")
    .execute();
  const out = [];
  for (const i of rows) {
    const decide = canDecide(p, r, i as Item);
    if (mine && !decide && i.decided_by !== p.userId) continue;
    out.push({
      id: i.id,
      user: { id: i.user_id, email: i.email, name: `${i.given_name} ${i.family_name}`.trim() || i.email, title: i.title, department: i.department, last_login_at: isoOrNull(i.last_login_at) },
      access: i.grant_kind === "role" ? `${i.grant_ref.replace("_", " ")} role` : i.via || (r.scope_type === "group" ? "member" : "assigned directly"),
      reviewer: i.reviewer_email ?? null,
      decision: i.decision,
      note: i.note,
      decided_by: i.decided_by_email ?? null,
      decided_at: isoOrNull(i.decided_at),
      outcome: i.outcome,
      you_can_decide: decide,
    });
  }
  return out;
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

async function load(tx: Tx, id: string) {
  const r = await tx.selectFrom("access_reviews").selectAll().where("id", "=", id).executeTakeFirst();
  if (!r) throw notFound("Access review");
  return r as Review & { closed_at: Date | null; summary: unknown; created_at: Date };
}

const csvCell = (v: unknown) => {
  const s = String(v ?? "");
  // Neutralise spreadsheet formulas, and quote.
  return `"${(/^[=+\-@\t\r]/.test(s) ? `'${s}` : s).replace(/"/g, '""')}"`;
};

export function registerAccessReviewRoutes(app: App) {
  const idParam = { params: z.object({ id: Id }) };

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/access-reviews",
      tags: ["Access reviews"],
      summary: "Start an access review (requires recent MFA)",
      description: "Snapshots who has the app, group or admin roles now, and asks the reviewers to keep or revoke each.",
      security: bearer,
      request: body(
        z.object({
          name: z.string().trim().min(1).max(200),
          scope: z.discriminatedUnion("type", [z.object({ type: z.literal("app"), id: Id }), z.object({ type: z.literal("group"), id: Id }), z.object({ type: z.literal("admin_roles") })]),
          reviewers: z.discriminatedUnion("kind", [
            z.object({ kind: z.literal("users"), ids: z.array(Id).min(1).max(20) }),
            z.object({ kind: z.literal("manager"), fallback_ids: z.array(Id).min(1).max(20).openapi({ description: "Review people who have no manager" }) }),
          ]),
          due_in_days: z.number().int().min(1).max(90).default(14),
          on_no_decision: z.enum(["keep", "revoke"]).default("keep"),
        }),
      ),
      responses: { 201: json(ReviewOut, "Started"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "access:manage");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const scope = { scope_type: input.scope.type, scope_id: "id" in input.scope ? input.scope.id : null };
        if (scope.scope_type !== "admin_roles") {
          const table = scope.scope_type === "app" ? "applications" : "groups";
          if (!(await tx.selectFrom(table).select("id").where("id", "=", scope.scope_id!).executeTakeFirst())) throw notFound(scope.scope_type === "app" ? "App" : "Group");
        }
        const reviewerIds = input.reviewers.kind === "users" ? input.reviewers.ids : input.reviewers.fallback_ids;
        const valid = await tx.selectFrom("users").select("id").where("id", "in", reviewerIds).where("status", "=", "active").execute();
        if (valid.length !== reviewerIds.length) throw badRequest("invalid_reviewer", "Reviewers must be active people in this organization");
        const grants = await snapshot(tx, scope);
        if (!grants.length) throw badRequest("nothing_to_review", "Nobody has this access right now");
        const id = newId();
        await tx
          .insertInto("access_reviews")
          .values({ id, org_id: p.orgId, name: input.name, ...scope, reviewer_kind: input.reviewers.kind, reviewer_ids: reviewerIds, on_no_decision: input.on_no_decision, due_at: new Date(Date.now() + input.due_in_days * 86_400_000), summary: "{}", created_by: p.userId })
          .execute();
        const managers =
          input.reviewers.kind === "manager"
            ? new Map((await tx.selectFrom("users").select(["id", "manager_id"]).where("id", "in", grants.map((g) => g.user_id)).execute()).map((u) => [u.id, u.manager_id]))
            : new Map<string, string | null>();
        const activeManagers = new Set(
          managers.size ? (await tx.selectFrom("users").select("id").where("id", "in", [...managers.values()].filter((x): x is string => !!x).concat(["00000000-0000-0000-0000-000000000000"])).where("status", "=", "active").execute()).map((u) => u.id) : [],
        );
        const reviewerFor = (userId: string) => {
          if (input.reviewers.kind === "users") return null; // any of the reviewers
          const m = managers.get(userId);
          if (m && activeManagers.has(m) && m !== userId) return m;
          return reviewerIds.find((x) => x !== userId) ?? reviewerIds[0]!;
        };
        await tx.insertInto("access_review_items").values(grants.map((g) => ({ id: newId(), org_id: p.orgId, review_id: id, ...g, reviewer_id: reviewerFor(g.user_id) }))).onConflict((oc) => oc.doNothing()).execute();
        const name = await scopeName(tx, scope);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "access.review_started", target: { type: "access_review", id, display: input.name }, details: { scope: { ...input.scope, name }, items: grants.length, reviewers: input.reviewers, due_in_days: input.due_in_days, on_no_decision: input.on_no_decision } });
        const items = (await tx.selectFrom("access_review_items").select(["reviewer_id", "user_id"]).where("review_id", "=", id).execute());
        const toTell = new Set<string>();
        for (const i of items) if (i.reviewer_id) toTell.add(i.reviewer_id); else for (const x of reviewerIds) if (x !== i.user_id) toTell.add(x);
        await notifyUsers(tx, p.orgId, [...toTell], {
          category: "access.review",
          title: `Review who has ${name}`,
          body: `“${input.name}”: keep or revoke each person's access by ${new Date(Date.now() + input.due_in_days * 86_400_000).toUTCString().slice(0, 16)}.`,
          entity: { type: "access_review", id },
          link: `/access-reviews/${id}`,
        });
        return reviewOut(tx, p, await load(tx, id));
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/access-reviews", tags: ["Access reviews"], summary: "Access reviews (all, for access admins; yours, for reviewers)", security: bearer, responses: { 200: json(z.object({ data: z.array(ReviewOut) })), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const rows = (await tx.selectFrom("access_reviews").selectAll().orderBy("created_at", "desc").limit(100).execute()) as (Review & { closed_at: Date | null; summary: unknown; created_at: Date })[];
        const out = [];
        for (const r of rows) {
          const o = await reviewOut(tx, p, r);
          if (can(p.roles, "access:manage") || r.reviewer_ids.includes(p.userId) || o.progress.yours_to_decide > 0) out.push(o);
        }
        return out;
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/access-reviews/{id}",
      tags: ["Access reviews"],
      summary: "A review and its items",
      description: "Access admins see every item; reviewers see what they can decide (or decided).",
      security: bearer,
      request: idParam,
      responses: { 200: json(z.object({ review: ReviewOut, items: z.array(ItemOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await load(tx, c.req.valid("param").id);
        const admin = can(p.roles, "access:manage");
        const items = await itemsOut(tx, p, r, !admin);
        if (!admin && !items.length && !r.reviewer_ids.includes(p.userId)) throw notFound("Access review");
        return { review: await reviewOut(tx, p, r), items };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/access-reviews/{id}/decisions",
      tags: ["Access reviews"],
      summary: "Keep or revoke (one or many items)",
      description: "Takes effect when the review closes. You can't decide your own access.",
      security: bearer,
      request: { ...idParam, ...body(z.object({ items: z.array(z.object({ id: Id, decision: z.enum(["keep", "revoke"]), note: z.string().trim().max(500).default("") })).min(1).max(500) })) },
      responses: { 200: json(z.object({ review: ReviewOut, items: z.array(ItemOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await load(tx, c.req.valid("param").id);
        if (r.status !== "open") throw conflict("closed", "This review is closed");
        for (const d of input.items) {
          const i = (await tx.selectFrom("access_review_items").selectAll().where("id", "=", d.id).where("review_id", "=", r.id).executeTakeFirst()) as Item | undefined;
          if (!i) throw notFound("Review item");
          if (!canDecide(p, r, i)) throw forbidden(i.user_id === p.userId ? "You can't review your own access" : "This item isn't yours to review");
          await tx.updateTable("access_review_items").set({ decision: d.decision, note: d.note, decided_by: p.userId, decided_at: new Date() }).where("id", "=", i.id).execute();
        }
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "access.review_decided",
          target: { type: "access_review", id: r.id, display: r.name },
          details: { keep: input.items.filter((d) => d.decision === "keep").length, revoke: input.items.filter((d) => d.decision === "revoke").length, items: input.items.map((d) => d.id) },
        });
        return { review: await reviewOut(tx, p, r), items: await itemsOut(tx, p, r, !can(p.roles, "access:manage")) };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/access-reviews/{id}/close",
      tags: ["Access reviews"],
      summary: "Close now and apply the decisions (requires recent MFA)",
      description: "Revokes what reviewers revoked; undecided items follow the review's default. It also closes itself at the due date.",
      security: bearer,
      request: idParam,
      responses: { 200: json(z.object({ review: ReviewOut, items: z.array(ItemOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "access:manage");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const id = c.req.valid("param").id;
        await closeReview(tx, p.orgId, id, c.get("meta"), { id: p.userId, email: p.email });
        const r = await load(tx, id);
        return { review: await reviewOut(tx, p, r), items: await itemsOut(tx, p, r, false) };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/access-reviews/{id}/export",
      tags: ["Access reviews"],
      summary: "The review as CSV (evidence for auditors)",
      security: bearer,
      request: idParam,
      responses: { 200: { description: "CSV", content: { "text/csv": { schema: z.string() } } }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "access:manage");
      const csv = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await load(tx, c.req.valid("param").id);
        const items = await itemsOut(tx, p, r, false);
        const head = ["review", "scope", "person", "email", "access", "reviewer", "decision", "note", "decided_by", "decided_at", "outcome", "closed_at"];
        const scope = await scopeName(tx, r);
        const rows = items.map((i) => [r.name, scope, i.user.name, i.user.email, i.access, i.reviewer ?? "any reviewer", i.decision ?? "", i.note, i.decided_by ?? "", i.decided_at ?? "", i.outcome, isoOrNull(r.closed_at) ?? ""]);
        return [head, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n") + "\r\n";
      });
      return c.body(csv, 200, { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="access-review-${c.req.valid("param").id}.csv"` });
    },
  );
}

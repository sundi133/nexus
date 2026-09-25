import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import type { App, Env, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa, requireSession } from "../auth/guard.js";
import { isUniqueViolation, type Tx } from "../platform/db.js";
import { badRequest, conflict, forbidden, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { can, ROLES } from "../rbac.js";
import { bearer, body, Id, iso, isoOrNull, json, patchOf, problemResponses } from "../schemas.js";
import { alreadyHas, approversFor, decide, endGrant, grant, isEligible, notifyApprovers, resourceName, type CatalogRow, type Stage } from "./requests.js";

const StageSchema = z
  .discriminatedUnion("kind", [
    z.object({ kind: z.literal("manager") }),
    z.object({ kind: z.literal("users"), ids: z.array(Id).min(1).max(20) }),
    z.object({ kind: z.literal("group"), id: Id }),
    z.object({ kind: z.literal("role"), role: z.enum(ROLES) }),
  ])
  .openapi("ApprovalStage");
const EligibleSchema = z.object({ users: z.array(Id).max(200).default([]), groups: z.array(Id).max(50).default([]) }).openapi("AccessEligible");
const JIT_ROLES = ["admin", "helpdesk", "security_analyst", "readonly"] as const;

const CatalogItem = z
  .object({
    id: Id,
    resource_type: z.enum(["app", "group", "role"]),
    resource_id: Id.nullable(),
    role: z.string().nullable(),
    name: z.string(),
    description: z.string(),
    enabled: z.boolean(),
    max_hours: z.number().int(),
    allow_permanent: z.boolean(),
    stages: z.array(StageSchema),
    eligible: EligibleSchema,
    you: z.object({ eligible: z.boolean(), has_access: z.boolean(), open_request: Id.nullable() }),
  })
  .openapi("AccessCatalogItem");

const RequestOut = z
  .object({
    id: Id,
    resource: z.object({ type: z.enum(["app", "group", "role"]), id: Id.nullable(), role: z.string().nullable(), name: z.string() }),
    requester: z.object({ id: Id, email: z.string() }),
    justification: z.string(),
    duration_hours: z.number().int().nullable(),
    status: z.enum(["pending", "active", "denied", "canceled", "ended", "revoked"]),
    stage: z.number().int().openapi({ description: "0-based index of the approval stage it waits on" }),
    stages: z.number().int(),
    approvers: z.array(z.string()).openapi({ description: "Who can decide the current stage (emails)" }),
    auto_approved: z.boolean(),
    decisions: z.array(z.object({ stage: z.number().int(), approver: z.string(), decision: z.enum(["approve", "deny"]), comment: z.string(), at: z.string() })),
    you_can_decide: z.boolean(),
    granted_at: z.string().nullable(),
    expires_at: z.string().nullable(),
    ended_at: z.string().nullable(),
    end_reason: z.string(),
    created_at: z.string(),
  })
  .openapi("AccessRequest");

async function catalogOut(tx: Tx, p: Principal, all: boolean): Promise<z.infer<typeof CatalogItem>[]> {
  let q = tx.selectFrom("access_catalog").selectAll().orderBy("created_at");
  if (!all) q = q.where("enabled", "=", true);
  const rows = await q.execute();
  const open = await tx.selectFrom("access_requests").select(["id", "catalog_id"]).where("requester_id", "=", p.userId).where("status", "in", ["pending", "active"]).execute();
  const out = [];
  for (const r of rows) {
    out.push({
      id: r.id,
      resource_type: r.resource_type,
      resource_id: r.resource_id,
      role: r.role,
      name: await resourceName(tx, r),
      description: r.description,
      enabled: r.enabled,
      max_hours: r.max_hours,
      allow_permanent: r.allow_permanent,
      stages: r.stages as unknown as z.infer<typeof StageSchema>[],
      eligible: { users: [], groups: [], ...(r.eligible as object) },
      you: { eligible: await isEligible(tx, r, p.userId), has_access: await alreadyHas(tx, r, p.userId), open_request: open.find((o) => o.catalog_id === r.id)?.id ?? null },
    });
  }
  return out;
}

async function requestOut(tx: Tx, p: Principal, id: string): Promise<z.infer<typeof RequestOut>> {
  const r = await tx.selectFrom("access_requests").selectAll().where("id", "=", id).executeTakeFirstOrThrow();
  const c = await tx.selectFrom("access_catalog").selectAll().where("id", "=", r.catalog_id).executeTakeFirstOrThrow();
  const stages = c.stages as unknown as Stage[];
  const requester = await tx.selectFrom("users").select(["id", "email"]).where("id", "=", r.requester_id).executeTakeFirstOrThrow();
  const decisions = await tx
    .selectFrom("access_decisions")
    .leftJoin("users", "users.id", "access_decisions.approver_id")
    .select(["access_decisions.stage", "access_decisions.decision", "access_decisions.comment", "access_decisions.at", "users.email"])
    .where("request_id", "=", id)
    .orderBy("at")
    .execute();
  const approvers = r.status === "pending" ? (await approversFor(tx, stages[r.stage], r.requester_id)).ids : [];
  const emails = approvers.length ? (await tx.selectFrom("users").select("email").where("id", "in", approvers).execute()).map((u) => u.email) : [];
  return {
    id: r.id,
    resource: { type: c.resource_type, id: c.resource_id, role: c.role, name: await resourceName(tx, c) },
    requester,
    justification: r.justification,
    duration_hours: r.duration_hours,
    status: r.status,
    stage: r.stage,
    stages: stages.length,
    approvers: emails,
    auto_approved: r.auto_approved,
    decisions: decisions.map((d) => ({ stage: d.stage, approver: d.email ?? "a removed user", decision: d.decision, comment: d.comment, at: iso(d.at) })),
    you_can_decide: approvers.includes(p.userId),
    granted_at: isoOrNull(r.granted_at),
    expires_at: isoOrNull(r.expires_at),
    ended_at: isoOrNull(r.ended_at),
    end_reason: r.end_reason,
    created_at: iso(r.created_at),
  };
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

/** Catalog references must be this organization's. */
async function checkRefs(tx: Tx, input: { resource_type?: string; resource_id?: string | null; stages?: Stage[]; eligible?: { users: string[]; groups: string[] } }) {
  const exists = async (table: "applications" | "groups" | "users", ids: string[]) => {
    if (!ids.length) return;
    const found = new Set((await tx.selectFrom(table).select("id").where("id", "in", ids).execute()).map((r) => r.id));
    const missing = ids.filter((i) => !found.has(i));
    if (missing.length) throw badRequest("unknown_reference", `Unknown ${table === "applications" ? "app" : table.slice(0, -1)}: ${missing.join(", ")}`);
  };
  if (input.resource_type === "app") await exists("applications", [input.resource_id!]);
  if (input.resource_type === "group") {
    await exists("groups", [input.resource_id!]);
    // Membership of dynamic and directory groups is decided elsewhere; a grant would be undone.
    const g = await tx.selectFrom("groups").select("rule").where("id", "=", input.resource_id!).executeTakeFirstOrThrow();
    if (g.rule) throw badRequest("dynamic_group", "Dynamic groups can't be requested: their members follow the group's rule");
    const linked = await tx.selectFrom("directory_links").select("local_id").where("kind", "=", "group").where("local_id", "=", input.resource_id!).executeTakeFirst();
    if (linked) throw badRequest("directory_managed", "This group's members come from a directory, so it can't be requested here");
  }
  for (const s of input.stages ?? []) {
    if (s.kind === "users") await exists("users", s.ids);
    if (s.kind === "group") await exists("groups", [s.id]);
  }
  await exists("users", input.eligible?.users ?? []);
  await exists("groups", input.eligible?.groups ?? []);
}

export function registerAccessRequestRoutes(app: App) {
  const idParam = { params: z.object({ id: Id }) };
  const CatalogIn = z.object({
    resource_type: z.enum(["app", "group", "role"]),
    resource_id: Id.optional(),
    role: z.enum(JIT_ROLES).optional().openapi({ description: "For role requests. Owner can't be requested." }),
    description: z.string().trim().max(500).default(""),
    enabled: z.boolean().default(true),
    max_hours: z.number().int().min(1).max(8760).default(168),
    allow_permanent: z.boolean().default(false),
    stages: z.array(StageSchema).max(5).default([{ kind: "role", role: "admin" }]),
    eligible: EligibleSchema.default({ users: [], groups: [] }),
  });

  // ---- Catalog ----------------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/access/catalog",
      tags: ["Access requests"],
      summary: "What you can request",
      description: "With access:manage and `all=true`, disabled entries too.",
      security: bearer,
      request: { query: z.object({ all: z.enum(["true", "false"]).optional() }) },
      responses: { 200: json(z.object({ data: z.array(CatalogItem) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const all = c.req.valid("query").all === "true" && can(p.roles, "access:manage");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => catalogOut(tx, p, all)) }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/access/catalog", tags: ["Access requests"], summary: "Make an app, group or admin role requestable (requires recent MFA)", security: bearer, request: body(CatalogIn), responses: { 201: json(z.object({ data: z.array(CatalogItem) }), "Created"), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "access:manage");
      const input = c.req.valid("json");
      if (input.resource_type === "role" ? !input.role || input.resource_id : !input.resource_id || input.role) throw badRequest("invalid_resource", "Role requests need a role; app and group requests need resource_id");
      if (input.resource_type === "role" && input.allow_permanent) throw badRequest("role_permanent", "Admin roles are always time-limited");
      try {
        const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          await stepUp(c, tx, p);
          await checkRefs(tx, input);
          const id = newId();
          await tx
            .insertInto("access_catalog")
            .values({ id, org_id: p.orgId, resource_type: input.resource_type, resource_id: input.resource_id ?? null, role: input.role ?? null, description: input.description, enabled: input.enabled, max_hours: input.max_hours, allow_permanent: input.allow_permanent, stages: JSON.stringify(input.stages), eligible: JSON.stringify(input.eligible), created_by: p.userId })
            .execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "access.catalog_created", target: { type: "access_catalog", id, display: await resourceName(tx, { resource_type: input.resource_type, resource_id: input.resource_id ?? null, role: input.role ?? null }) }, details: input });
          return catalogOut(tx, p, true);
        });
        return c.json({ data }, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("already_requestable", "That's already in the catalog");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/access/catalog/{id}",
      tags: ["Access requests"],
      summary: "Change how something is requested and approved (requires recent MFA)",
      security: bearer,
      request: { ...idParam, ...body(patchOf(CatalogIn.omit({ resource_type: true, resource_id: true, role: true }))) },
      responses: { 200: json(z.object({ data: z.array(CatalogItem) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "access:manage");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const before = await tx.selectFrom("access_catalog").selectAll().where("id", "=", id).executeTakeFirst();
        if (!before) throw notFound("Catalog entry");
        if (before.resource_type === "role" && input.allow_permanent) throw badRequest("role_permanent", "Admin roles are always time-limited");
        await checkRefs(tx, input);
        const set: Record<string, unknown> = { ...input, updated_at: new Date() };
        if (input.stages) set.stages = JSON.stringify(input.stages);
        if (input.eligible) set.eligible = JSON.stringify(input.eligible);
        await tx.updateTable("access_catalog").set(set).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "access.catalog_updated", target: { type: "access_catalog", id, display: await resourceName(tx, before) }, details: { changes: input } });
        return catalogOut(tx, p, true);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/access/catalog/{id}", tags: ["Access requests"], summary: "Stop offering something (open requests are canceled; active grants keep their end time)", security: bearer, request: idParam, responses: { 200: json(z.object({ data: z.array(CatalogItem) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "access:manage");
      const { id } = c.req.valid("param");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const before = await tx.selectFrom("access_catalog").selectAll().where("id", "=", id).executeTakeFirst();
        if (!before) throw notFound("Catalog entry");
        // Active grants must still end: keep the entry, just switch it off.
        const active = await tx.selectFrom("access_requests").select("id").where("catalog_id", "=", id).where("status", "=", "active").executeTakeFirst();
        await tx.updateTable("access_requests").set({ status: "canceled", ended_at: new Date(), end_reason: "No longer requestable" }).where("catalog_id", "=", id).where("status", "=", "pending").execute();
        if (active) await tx.updateTable("access_catalog").set({ enabled: false, updated_at: new Date() }).where("id", "=", id).execute();
        else await tx.deleteFrom("access_catalog").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "access.catalog_deleted", target: { type: "access_catalog", id, display: await resourceName(tx, before) } });
        return catalogOut(tx, p, true);
      });
      return c.json({ data }, 200);
    },
  );

  // ---- Requests ---------------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/access/requests",
      tags: ["Access requests"],
      summary: "Request access",
      description: "Pre-approved (eligible) people get it at once, after a recent MFA; everyone else waits for the approval stages.",
      security: bearer,
      request: body(z.object({ catalog_id: Id, justification: z.string().trim().min(5).max(1000), duration_hours: z.number().int().min(1).max(8760).nullable().default(null).openapi({ description: "null: permanent (only where allowed)" }) })),
      responses: { 201: json(RequestOut, "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const input = c.req.valid("json");
      const meta = c.get("meta");
      try {
        const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          const cat = await tx.selectFrom("access_catalog").selectAll().where("id", "=", input.catalog_id).where("enabled", "=", true).executeTakeFirst();
          if (!cat) throw notFound("Requestable access");
          if (input.duration_hours === null && !cat.allow_permanent) throw badRequest("duration_required", `Choose how long you need it (up to ${cat.max_hours} h)`);
          if (input.duration_hours !== null && input.duration_hours > cat.max_hours) throw badRequest("too_long", `At most ${cat.max_hours} h`);
          if (await alreadyHas(tx, cat, p.userId)) throw conflict("already_has_access", "You already have this");
          const eligible = await isEligible(tx, cat, p.userId);
          if (eligible) await stepUp(c, tx, p); // self-activation: prove it's you
          else if (!(await approversFor(tx, (cat.stages as unknown as Stage[])[0], p.userId)).ids.length) throw conflict("no_approver", "Nobody else can approve this yet. Ask an admin to set up approvers.");
          const id = newId();
          const req = { id, org_id: p.orgId, catalog_id: cat.id, requester_id: p.userId, justification: input.justification, duration_hours: input.duration_hours, status: "pending", stage: 0, expires_at: null };
          await tx.insertInto("access_requests").values({ id, org_id: p.orgId, catalog_id: cat.id, requester_id: p.userId, justification: input.justification, duration_hours: input.duration_hours, auto_approved: eligible }).execute();
          const what = await resourceName(tx, cat);
          await audit(tx, p.orgId, { principal: p, meta }, { type: "access.requested", target: { type: "access_catalog", id: cat.id, display: what }, details: { request_id: id, justification: input.justification, duration_hours: input.duration_hours, eligible } });
          if (eligible || !(cat.stages as unknown as Stage[]).length) await grant(tx, cat, req, meta, eligible ? `Pre-approved; activated by ${p.email}: ${input.justification}` : input.justification);
          else await notifyApprovers(tx, cat, req);
          return requestOut(tx, p, id);
        });
        return c.json(out, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("already_requested", "You already have an open request for this");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/access/requests",
      tags: ["Access requests"],
      summary: "Access requests",
      description: "view=mine (default), approvals (waiting on you), all (access:manage).",
      security: bearer,
      request: { query: z.object({ view: z.enum(["mine", "approvals", "all"]).default("mine"), status: z.enum(["pending", "active", "denied", "canceled", "ended", "revoked"]).optional(), limit: z.coerce.number().int().min(1).max(200).default(100) }) },
      responses: { 200: json(z.object({ data: z.array(RequestOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const q = c.req.valid("query");
      if (q.view === "all" && !can(p.roles, "access:manage")) throw forbidden();
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        let s = tx.selectFrom("access_requests").select("id").orderBy("created_at", "desc").limit(q.view === "approvals" ? 500 : q.limit);
        if (q.view === "mine") s = s.where("requester_id", "=", p.userId);
        if (q.view === "approvals") s = s.where("status", "=", "pending");
        if (q.status) s = s.where("status", "=", q.status);
        const out = [];
        for (const r of await s.execute()) {
          const o = await requestOut(tx, p, r.id);
          if (q.view !== "approvals" || o.you_can_decide) out.push(o);
        }
        return out.slice(0, q.limit);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/access/requests/{id}/decision",
      tags: ["Access requests"],
      summary: "Approve or deny (approving an admin role requires recent MFA)",
      security: bearer,
      request: { ...idParam, ...body(z.object({ decision: z.enum(["approve", "deny"]), comment: z.string().trim().max(1000).default("") })) },
      responses: { 200: json(RequestOut), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const req = await tx.selectFrom("access_requests").selectAll().where("id", "=", id).forUpdate().executeTakeFirst();
        if (!req) throw notFound("Access request");
        if (req.status !== "pending") throw conflict("not_pending", `This request is already ${req.status}`);
        if (req.requester_id === p.userId) throw forbidden("You can't decide your own request");
        const cat = await tx.selectFrom("access_catalog").selectAll().where("id", "=", req.catalog_id).executeTakeFirstOrThrow();
        if (input.decision === "approve" && cat.resource_type === "role") await stepUp(c, tx, p);
        await decide(tx, cat as CatalogRow, req, { id: p.userId, email: p.email }, input.decision, input.comment, c.get("meta"));
        return requestOut(tx, p, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/access/requests/{id}/cancel", tags: ["Access requests"], summary: "Withdraw your pending request", security: bearer, request: idParam, responses: { 200: json(RequestOut), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.updateTable("access_requests").set({ status: "canceled", ended_at: new Date(), end_reason: "Withdrawn" }).where("id", "=", id).where("requester_id", "=", p.userId).where("status", "=", "pending").returning("id").executeTakeFirst();
        if (!r) throw conflict("not_cancelable", "Only your own pending requests can be withdrawn");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "access.request_canceled", target: { type: "access_request", id }, details: { request_id: id } });
        return requestOut(tx, p, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/access/requests/{id}/revoke",
      tags: ["Access requests"],
      summary: "End a grant now (requires recent MFA)",
      description: "For access admins, or the requester giving it back early.",
      security: bearer,
      request: { ...idParam, ...body(z.object({ reason: z.string().trim().max(500).default("") })) },
      responses: { 200: json(RequestOut), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const { reason } = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const req = await tx.selectFrom("access_requests").selectAll().where("id", "=", id).forUpdate().executeTakeFirst();
        if (!req) throw notFound("Access request");
        const own = req.requester_id === p.userId;
        if (!own && !can(p.roles, "access:manage")) throw forbidden();
        if (req.status !== "active") throw conflict("not_active", "Only active grants can be ended");
        if (!own) await stepUp(c, tx, p);
        const cat = await tx.selectFrom("access_catalog").selectAll().where("id", "=", req.catalog_id).executeTakeFirstOrThrow();
        await endGrant(tx, cat as CatalogRow, req, c.get("meta"), { status: "revoked", reason: reason || (own ? "Given back early" : `Revoked by ${p.email}`), by: { id: p.userId, email: p.email } });
        return requestOut(tx, p, id);
      });
      return c.json(out, 200);
    },
  );
}

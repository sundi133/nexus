import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { requirePermission } from "../auth/guard.js";
import { decodeCursor, pageOf } from "../platform/pagination.js";
import { AuditEvent, bearer, Cursor, Id, iso, json, page, problemResponses } from "../schemas.js";
import type { Tx } from "../platform/db.js";

export const auditQuery = (tx: Tx) => tx.selectFrom("audit_events").selectAll();

type Row = Awaited<ReturnType<ReturnType<typeof auditQuery>["executeTakeFirstOrThrow"]>>;

export const toAuditEvent = (e: Row) => ({
  id: e.id,
  ts: iso(e.ts),
  type: e.type,
  outcome: e.outcome,
  actor: { type: e.actor_type, id: e.actor_id, display: e.actor_display },
  target: { type: e.target_type, id: e.target_id, display: e.target_display },
  session_id: e.session_id,
  ip: e.ip,
  user_agent: e.user_agent,
  details: e.details,
});

export function registerAuditRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/audit/events",
      tags: ["Audit"],
      summary: "Search the audit log (newest first)",
      security: bearer,
      request: {
        query: Cursor.extend({
          type: z.string().max(100).optional().openapi({ description: "Exact type, or a prefix ending in `*` (e.g. `auth.*`)" }),
          outcome: z.enum(["success", "failure", "denied"]).optional(),
          actor_id: Id.optional(),
          target_id: Id.optional(),
          subject_id: Id.optional().openapi({ description: "Events where this ID is the actor or the target" }),
          since: z.iso.datetime().optional(),
          until: z.iso.datetime().optional(),
        }),
      },
      responses: { 200: json(page(AuditEvent, "AuditEventPage")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "audit:read");
      const q = c.req.valid("query");
      const after = decodeCursor(q.cursor);
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) => {
        let query = auditQuery(tx).orderBy("id", "desc").limit(q.limit + 1);
        if (after) query = query.where("id", "<", after);
        if (q.type?.endsWith("*")) query = query.where("type", "like", `${q.type.slice(0, -1).replace(/[%_\\]/g, "\\$&")}%`);
        else if (q.type) query = query.where("type", "=", q.type);
        if (q.outcome) query = query.where("outcome", "=", q.outcome);
        if (q.actor_id) query = query.where("actor_id", "=", q.actor_id);
        if (q.target_id) query = query.where("target_id", "=", q.target_id);
        if (q.subject_id) query = query.where((eb) => eb.or([eb("actor_id", "=", q.subject_id!), eb("target_id", "=", q.subject_id!)]));
        if (q.since) query = query.where("ts", ">=", new Date(q.since));
        if (q.until) query = query.where("ts", "<", new Date(q.until));
        return query.execute();
      });
      const pg = pageOf(rows, q.limit);
      return c.json({ data: pg.data.map(toAuditEvent), next_cursor: pg.next_cursor }, 200);
    },
  );
}

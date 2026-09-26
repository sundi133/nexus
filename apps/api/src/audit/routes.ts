import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { requirePermission } from "../auth/guard.js";
import { decodeCursor, pageOf } from "../platform/pagination.js";
import { AuditEvent, bearer, Cursor, Id, iso, json, page, problemResponses } from "../schemas.js";
import type { Tx } from "../platform/db.js";
import { sql } from "kysely";
import { getSettings } from "../org/settings.js";
import { seal, verify } from "./integrity.js";

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

const Integrity = z
  .object({
    ok: z.boolean(),
    blocks_checked: z.number().int(),
    events_checked: z.number().int(),
    pruned_blocks: z.number().int().openapi({ description: "Blocks whose events were removed by retention; their digests remain in the chain" }),
    head: z.object({ block: z.number().int(), digest: z.string(), sealed_at: z.string() }).nullable().openapi({ description: "The latest seal. Compare its digest with the audit.sealed events in your SIEM or archive." }),
    problem: z.object({ block: z.number().int(), kind: z.string(), detail: z.string() }).nullable(),
    unsealed_events: z.number().int().openapi({ description: "Events newer than the latest seal (sealed within the hour)" }),
    retention_days: z.number().int(),
  })
  .openapi("AuditIntegrity");

const Block = z
  .object({ block: z.number().int(), events: z.number().int(), first_ts: z.string(), last_ts: z.string(), prev_digest: z.string(), digest: z.string(), sealed_at: z.string(), pruned: z.boolean() })
  .openapi("AuditBlock");

export function registerAuditRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/audit/integrity",
      tags: ["Audit"],
      summary: "Verify the audit log",
      description: "Recomputes the hash chain over every retained event and checks that the sealed blocks link up. Any changed, removed or inserted event is reported with its block.",
      security: bearer,
      responses: { 200: json(Integrity), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "audit:read");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const v = await verify(tx);
        const head = await tx.selectFrom("audit_blocks").select(["to_txid", "to_id"]).orderBy("seq", "desc").limit(1).executeTakeFirst();
        const unsealed = await sql<{ n: number }>`SELECT count(*)::int AS n FROM audit_events e WHERE ${head ? sql`(e.txid, e.id) > (${head.to_txid}::xid8, ${head.to_id}::uuid)` : sql`true`}`.execute(tx);
        return { ...v, unsealed_events: unsealed.rows[0]!.n, retention_days: (await getSettings(tx, p.orgId)).audit_retention_days };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/audit/blocks",
      tags: ["Audit"],
      summary: "List sealed blocks (newest first)",
      description: "The chain of digests, for anchoring elsewhere or independent verification.",
      security: bearer,
      request: { query: z.object({ limit: z.coerce.number().int().min(1).max(500).default(50) }) },
      responses: { 200: json(z.object({ data: z.array(Block) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "audit:read");
      const { limit } = c.req.valid("query");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) => tx.selectFrom("audit_blocks").selectAll().orderBy("seq", "desc").limit(limit).execute());
      return c.json({ data: rows.map((b) => ({ block: Number(b.seq), events: b.count, first_ts: iso(b.first_ts), last_ts: iso(b.last_ts), prev_digest: b.prev_digest, digest: b.digest, sealed_at: iso(b.sealed_at), pruned: !!b.pruned_at })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/audit/seal",
      tags: ["Audit"],
      summary: "Seal the audit log now",
      description: "Seals committed events into a new block (this also happens hourly).",
      security: bearer,
      responses: { 200: json(z.object({ sealed: Block.pick({ block: true, events: true, digest: true }).nullable() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const r = await seal(c.get("deps"), p.orgId, c.get("meta"));
      return c.json({ sealed: r ? { block: r.seq, events: r.count, digest: r.digest } : null }, 200);
    },
  );

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

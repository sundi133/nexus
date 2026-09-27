import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { problemResponses, bearer } from "../schemas.js";
import { exportColumns, selectKept, SKIP_TABLES } from "./columns.js";

/**
 * The whole organization's data, for portability and for leaving: gzipped JSON lines from one
 * consistent snapshot, streamed so any size works. Secrets are left out (and listed).
 *
 *   {"type":"manifest","format":"nexus-org-export/1","organization":{…},"exported_at":…}
 *   {"type":"table","table":"users","columns":[…],"omitted":["password_hash"]}
 *   {"type":"row","table":"users","row":{…}}              one per row
 *   {"type":"end","counts":{"users":42,…}}                 absent if the export was cut short
 */

const BATCH = 1000;

/** Tenant tables (they have org_id), in name order, minus internal ones. */
async function tenantTables(tx: Tx) {
  const rows = (
    await sql<{ name: string }>`
      SELECT c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'
        AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'org_id' AND NOT a.attisdropped)
      ORDER BY 1`.execute(tx)
  ).rows;
  return rows.map((r) => r.name).filter((t) => !SKIP_TABLES.has(t));
}

async function streamExport(deps: Deps, orgId: string, out: WritableStreamDefaultWriter<Uint8Array>) {
  const enc = new TextEncoder();
  const line = (o: unknown) => out.write(enc.encode(JSON.stringify(o) + "\n"));
  const counts: Record<string, number> = {};
  // One snapshot: rows written while the export runs don't make it inconsistent.
  await deps.db.kysely.transaction().setIsolationLevel("repeatable read").execute(async (tx) => {
    await sql`SELECT set_config('app.org_id', ${orgId}, true)`.execute(tx);
    const org = (await sql<Record<string, unknown>>`SELECT id, name, slug, settings, created_at FROM organizations WHERE id = ${orgId}`.execute(tx)).rows[0];
    await line({ type: "manifest", format: "nexus-org-export/1", organization: org, exported_at: new Date().toISOString() });
    for (const table of await tenantTables(tx)) {
      const cols = await exportColumns(tx, table);
      await line({ type: "table", table, columns: cols.keep, omitted: cols.dropped });
      await sql`DECLARE nexus_export NO SCROLL CURSOR FOR ${selectKept(table, cols, sql`org_id = ${orgId}`)}`.execute(tx);
      let n = 0;
      for (;;) {
        const rows = (await sql<Record<string, unknown>>`FETCH ${sql.raw(String(BATCH))} FROM nexus_export`.execute(tx)).rows;
        for (const row of rows) await line({ type: "row", table, row });
        n += rows.length;
        if (rows.length < BATCH) break;
      }
      await sql`CLOSE nexus_export`.execute(tx);
      counts[table] = n;
    }
  });
  await line({ type: "end", counts });
}

export function registerOrgExportRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/org/export",
      tags: ["Data"],
      summary: "Export all of the organization's data",
      description:
        "Gzipped JSON lines from one consistent snapshot: a manifest, then each table's columns and rows, then an `end` line with row counts (missing if the download was cut short). Secrets (password hashes, sealed credentials, key material, token hashes) are left out and listed per table. Needs `data:export`; recorded in the audit log.",
      security: bearer,
      responses: { 200: { description: "nexus-org-export/1 (application/gzip)", content: { "application/gzip": { schema: z.string().openapi({ format: "binary" }) } } }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "data:export");
      const deps = c.get("deps");
      const name = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "organization.exported", details: {} });
        return (await tx.selectFrom("organizations").select("slug").where("id", "=", p.orgId).executeTakeFirstOrThrow()).slug;
      });
      const pipe = new TransformStream<Uint8Array, Uint8Array>();
      const writer = pipe.writable.getWriter();
      void streamExport(deps, p.orgId, writer).then(
        () => writer.close(),
        (err) => {
          console.error(`[export] ${p.orgId} failed:`, err);
          void writer.abort(err).catch(() => {});
        },
      );
      const date = new Date().toISOString().slice(0, 10);
      return c.body(pipe.readable.pipeThrough(new CompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>), 200, {
        "content-type": "application/gzip",
        "content-disposition": `attachment; filename="nexus-${name}-${date}.ndjson.gz"`,
      }) as never;
    },
  );
}

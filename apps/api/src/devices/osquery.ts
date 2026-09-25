import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { assertDeviceInScope, requirePermission, requireRecentMfa, scopeGroups } from "../auth/guard.js";
import { notPrivileged } from "../directory/privileged.js";
import type { Tx } from "../platform/db.js";
import { badRequest, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { QueryResult } from "./commands.js";

/**
 * osquery (DEV inventory, live query). The agent runs a scheduled pack
 * (software, listening ports, USB devices, browser extensions, startup items)
 * and reports it on check-in; admins with devices:query can also run one SQL
 * statement on many devices at once. A live query travels as a command signed
 * with the organization's key, SQL included, so the agent runs exactly what
 * an admin asked for; both sides refuse tables that reach the network or read
 * file contents.
 */

export const OSQUERY_INTERVAL_S = 6 * 3600;
const LIVE_QUERY_TTL_MS = 10 * 60_000;
const MAX_TARGETS = 1000;

// ---- What the agent reports ----------------------------------------------------------------

const Row = z.record(z.string().max(200), z.string().max(20_000));
export const OsqueryReport = z.object({
  available: z.boolean(),
  version: z.string().max(40).default(""),
  collected_at: z.string().datetime(),
  results: z
    .array(z.object({ name: z.string().regex(/^[a-z_]{1,50}$/), rows: z.array(Row).max(5000), truncated: z.boolean().optional(), error: z.string().max(1000).optional() }))
    .max(20),
});
export type OsqueryReport = z.infer<typeof OsqueryReport>;

/** Stores a device's pack results (replacing the previous ones). */
export async function storeOsquery(tx: Tx, device: { id: string; org_id: string }, rep: OsqueryReport) {
  const at = new Date(rep.collected_at);
  await tx
    .updateTable("devices")
    .set({ osquery_version: rep.available ? rep.version || "unknown" : "", osquery_collected_at: at })
    .where("id", "=", device.id)
    .execute();
  if (!rep.available) return;
  for (const r of rep.results) {
    await tx
      .insertInto("device_osquery")
      .values({ org_id: device.org_id, device_id: device.id, name: r.name, rows: JSON.stringify(r.rows), truncated: !!r.truncated, error: r.error ?? "", collected_at: at })
      .onConflict((oc) => oc.columns(["device_id", "name"]).doUpdateSet((eb) => ({ rows: eb.ref("excluded.rows"), truncated: eb.ref("excluded.truncated"), error: eb.ref("excluded.error"), collected_at: eb.ref("excluded.collected_at") })))
      .execute();
  }
  const names = rep.results.map((r) => r.name);
  let del = tx.deleteFrom("device_osquery").where("device_id", "=", device.id);
  if (names.length) del = del.where("name", "not in", names);
  await del.execute();
}

// ---- What queries may do (the agent checks the same) ----------------------------------------

const DENIED = /\b(curl|curl_certificate|carves|carve|yara|yara_events|attach|pragma|detach)\b/i;
const LEADING = /^\s*(?:--[^\n]*\n\s*|\/\*[\s\S]*?\*\/\s*)*(select|with)\b/i;

export function checkSQL(raw: string): string | null {
  const s = raw.trim().replace(/;$/, "");
  if (!s) return "Write a query";
  if (s.length > 10_000) return "The query is too long";
  if (!LEADING.test(s)) return "Only SELECT queries are allowed";
  if (s.replace(/'[^']*'|"[^"]*"/g, "").includes(";")) return "One statement at a time";
  const m = DENIED.exec(s);
  if (m) return `"${m[1]!.toLowerCase()}" isn't allowed in Nexus queries: it reaches the network or reads file contents`;
  return null;
}

// ---- API ---------------------------------------------------------------------------------------

const OsqueryTable = z.object({ name: z.string(), rows: z.array(z.record(z.string(), z.string())), truncated: z.boolean(), error: z.string(), collected_at: z.string() });
const DeviceOsquery = z
  .object({
    status: z.enum(["not_reported", "not_installed", "installed"]),
    version: z.string().nullable(),
    collected_at: z.string().nullable(),
    tables: z.array(OsqueryTable),
  })
  .openapi("DeviceOsquery");

const SoftwareItem = z.object({ name: z.string(), source: z.string(), devices: z.number().int(), versions: z.array(z.object({ version: z.string(), devices: z.number().int() })) }).openapi("SoftwareItem");

const LiveTarget = z
  .object({
    device_ids: z.array(Id).max(MAX_TARGETS).optional(),
    group_id: Id.optional(),
    all: z.boolean().optional(),
  })
  .refine((t) => [t.device_ids?.length ? 1 : 0, t.group_id ? 1 : 0, t.all ? 1 : 0].reduce((a, b) => a + b, 0) === 1, "Pick devices, a group, or all devices");

const LiveQuerySummary = z
  .object({
    id: Id,
    sql: z.string(),
    reason: z.string(),
    requested_by: z.string().nullable(),
    created_at: z.string(),
    expires_at: z.string(),
    devices: z.number().int(),
    done: z.number().int(),
    failed: z.number().int(),
    pending: z.number().int(),
  })
  .openapi("LiveQuerySummary");

const LiveQueryDetail = LiveQuerySummary.extend({
  results: z.array(
    z.object({
      device_id: Id,
      hostname: z.string(),
      status: z.enum(["queued", "sent", "done", "failed", "expired", "canceled"]),
      message: z.string(),
      rows: z.number().int(),
      truncated: z.boolean(),
      finished_at: z.string().nullable(),
    }),
  ),
  columns: z.array(z.string()),
  rows: z.array(z.record(z.string(), z.string())).openapi({ description: "Every device's rows, each with a `_device` column (up to 10,000 rows)" }),
}).openapi("LiveQueryDetail");

/** Devices a scoped admin may see (group scope), for device-read endpoints. */
function scoped<T extends { where: (...a: any[]) => T }>(q: T, scope: string[] | null) {
  if (!scope) return q;
  return (q as any)
    .where((eb: any) => eb.exists(eb.selectFrom("group_members").whereRef("group_members.user_id", "=", "devices.primary_user_id").where("group_members.group_id", "in", scope)))
    .where(notPrivileged("devices.primary_user_id")) as T;
}

async function summaries(tx: Tx, ids?: string[]) {
  let q = tx
    .selectFrom("live_queries")
    .leftJoin("users", "users.id", "live_queries.requested_by")
    .select(["live_queries.id", "live_queries.sql", "live_queries.reason", "live_queries.created_at", "live_queries.expires_at", "live_queries.device_count", "users.email"])
    .select((eb) => [
      eb.selectFrom("device_commands").whereRef("device_commands.query_id", "=", "live_queries.id").where("device_commands.status", "=", "done").select(sql<number>`count(*)::int`.as("n")).as("done"),
      eb.selectFrom("device_commands").whereRef("device_commands.query_id", "=", "live_queries.id").where("device_commands.status", "in", ["failed", "expired", "canceled"]).select(sql<number>`count(*)::int`.as("n")).as("failed"),
    ])
    .orderBy("live_queries.created_at", "desc");
  if (ids) q = q.where("live_queries.id", "in", ids);
  else q = q.limit(50);
  return (await q.execute()).map((r) => ({
    id: r.id,
    sql: r.sql,
    reason: r.reason,
    requested_by: r.email,
    created_at: iso(r.created_at),
    expires_at: iso(r.expires_at),
    devices: r.device_count,
    done: r.done ?? 0,
    failed: r.failed ?? 0,
    pending: r.device_count - (r.done ?? 0) - (r.failed ?? 0),
  }));
}

export function registerOsqueryRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/devices/{id}/osquery",
      tags: ["Devices"],
      summary: "A device's osquery inventory: software, listening ports, USB devices, browser extensions, startup items",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(DeviceOsquery), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertDeviceInScope(tx, p, "devices:read", id);
        const d = await tx.selectFrom("devices").select(["osquery_version", "osquery_collected_at"]).where("id", "=", id).executeTakeFirst();
        if (!d) throw notFound("Device");
        const rows = await tx.selectFrom("device_osquery").selectAll().where("device_id", "=", id).orderBy("name").execute();
        return {
          status: d.osquery_version === null ? ("not_reported" as const) : d.osquery_version === "" ? ("not_installed" as const) : ("installed" as const),
          version: d.osquery_version || null,
          collected_at: isoOrNull(d.osquery_collected_at),
          tables: rows.map((r) => ({ name: r.name, rows: r.rows, truncated: r.truncated, error: r.error, collected_at: iso(r.collected_at) })),
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/software",
      tags: ["Devices"],
      summary: "Software across devices (from osquery), with the versions in use",
      security: bearer,
      request: { query: z.object({ q: z.string().trim().max(200).optional(), limit: z.coerce.number().int().min(1).max(1000).default(200) }) },
      responses: { 200: json(z.object({ data: z.array(SoftwareItem), devices_reporting: z.number().int() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const q = c.req.valid("query");
      const scope = scopeGroups(p, "devices:read");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const like = q.q ? `%${q.q.replace(/[%_\\]/g, "\\$&")}%` : null;
        const base = () => {
          let b = tx
            .selectFrom("device_osquery")
            .innerJoin("devices", "devices.id", "device_osquery.device_id")
            .innerJoin(sql<{ r: unknown }>`jsonb_array_elements(device_osquery.rows)`.as("e"), (j) => j.onTrue())
            .where("device_osquery.name", "=", "software")
            .where("devices.status", "=", "active");
          if (like) b = b.where(sql<boolean>`e.value->>'name' ILIKE ${like}`);
          return scoped(b, scope);
        };
        const name = sql<string>`e.value->>'name'`.as("name");
        const source = sql<string>`coalesce(e.value->>'source', '')`.as("source");
        const devices = sql<number>`count(DISTINCT devices.id)::int`.as("devices");
        const rows = await base()
          .select([name, source, sql<string>`coalesce(e.value->>'version', '')`.as("version"), devices])
          .groupBy([sql`1`, sql`2`, sql`3`])
          .execute();
        const totals = await base().select([name, source, devices]).groupBy([sql`1`, sql`2`]).execute();
        const reporting = await scoped(tx.selectFrom("devices").where("devices.status", "=", "active").where("devices.osquery_version", "<>", ""), scope)
          .select(sql<number>`count(*)::int`.as("n"))
          .executeTakeFirst();
        const byName = new Map<string, z.infer<typeof SoftwareItem>>();
        for (const t of totals) byName.set(`${t.name}\u0000${t.source}`, { name: t.name, source: t.source, devices: t.devices, versions: [] });
        for (const r of rows) byName.get(`${r.name}\u0000${r.source}`)?.versions.push({ version: r.version, devices: r.devices });
        const data = [...byName.values()]
          .map((s) => ({ ...s, versions: s.versions.sort((a, b) => b.devices - a.devices || b.version.localeCompare(a.version, undefined, { numeric: true })) }))
          .sort((a, b) => b.devices - a.devices || a.name.localeCompare(b.name))
          .slice(0, q.limit);
        return { data, devices_reporting: reporting?.n ?? 0 };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/software/devices",
      tags: ["Devices"],
      summary: "Devices that have a given piece of software (optionally one version)",
      security: bearer,
      request: { query: z.object({ name: z.string().max(500), source: z.string().max(50).optional(), version: z.string().max(200).optional() }) },
      responses: { 200: json(z.object({ data: z.array(z.object({ device_id: Id, hostname: z.string(), user_email: z.string().nullable(), version: z.string() })) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const q = c.req.valid("query");
      const scope = scopeGroups(p, "devices:read");
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        let query = tx
          .selectFrom("device_osquery")
          .innerJoin("devices", "devices.id", "device_osquery.device_id")
          .leftJoin("users", "users.id", "devices.primary_user_id")
          .innerJoin(sql<{ r: unknown }>`jsonb_array_elements(device_osquery.rows)`.as("e"), (j) => j.onTrue())
          .where("device_osquery.name", "=", "software")
          .where("devices.status", "=", "active")
          .where(sql<boolean>`e.value->>'name' = ${q.name}`);
        if (q.source) query = query.where(sql<boolean>`e.value->>'source' = ${q.source}`);
        if (q.version !== undefined) query = query.where(sql<boolean>`coalesce(e.value->>'version', '') = ${q.version}`);
        query = scoped(query, scope);
        return query
          .select(["devices.id", "devices.hostname", "users.email", sql<string>`coalesce(e.value->>'version', '')`.as("version")])
          .orderBy("devices.hostname")
          .limit(1000)
          .execute();
      });
      return c.json({ data: rows.map((r) => ({ device_id: r.id, hostname: r.hostname, user_email: r.email, version: r.version })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/live-queries",
      tags: ["Devices"],
      summary: "Run an osquery SQL query on devices",
      description:
        "Sends one SELECT statement to the chosen devices as signed commands; each runs it on its next check-in (about a minute) and returns up to 1,000 rows. Needs `devices:query` and a recent MFA. Tables that reach the network or read file contents (curl, carves, yara) are refused.",
      security: bearer,
      request: body(z.object({ sql: z.string().min(1).max(10_000), reason: z.string().trim().min(3).max(500), target: LiveTarget })),
      responses: { 201: json(LiveQuerySummary.extend({ skipped_without_osquery: z.number().int() }), "Sent"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:query");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const bad = checkSQL(input.sql);
      if (bad) throw badRequest("invalid_query", bad);
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        let q = tx.selectFrom("devices").select(["devices.id", "devices.osquery_version"]).where("devices.status", "=", "active");
        if (input.target.device_ids?.length) q = q.where("devices.id", "in", input.target.device_ids);
        if (input.target.group_id) q = q.where((eb) => eb.exists(eb.selectFrom("group_members").whereRef("group_members.user_id", "=", "devices.primary_user_id").where("group_members.group_id", "=", input.target.group_id!)));
        const found = await q.limit(MAX_TARGETS + 1).execute();
        if (found.length > MAX_TARGETS) throw badRequest("too_many_devices", `A live query goes to at most ${MAX_TARGETS} devices; narrow the target`);
        const targets = found.filter((d) => d.osquery_version !== ""); // known not to have osquery: skip
        if (!targets.length) throw badRequest("no_devices", found.length ? "None of these devices has osquery installed" : "No devices match");
        const id = newId();
        const expires = new Date(Date.now() + LIVE_QUERY_TTL_MS);
        const sqlText = input.sql.trim();
        await tx
          .insertInto("live_queries")
          .values({ id, org_id: p.orgId, sql: sqlText, reason: input.reason, target: JSON.stringify(input.target), device_count: targets.length, requested_by: p.userId, expires_at: expires })
          .execute();
        await tx
          .insertInto("device_commands")
          .values(targets.map((d) => ({ id: newId(), org_id: p.orgId, device_id: d.id, action: "osquery" as const, channel: "agent" as const, reason: input.reason, requested_by: p.userId, expires_at: expires, args: JSON.stringify({ sql: sqlText }), query_id: id })))
          .execute();
        await auditLiveQuery(tx, p, c.get("meta"), { id, sql: sqlText, reason: input.reason, target: input.target, devices: targets.length, skipped: found.length - targets.length });
        return { ...(await summaries(tx, [id]))[0]!, skipped_without_osquery: found.length - targets.length };
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/live-queries", tags: ["Devices"], summary: "Recent live queries", security: bearer, responses: { 200: json(z.object({ data: z.array(LiveQuerySummary) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:query");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => summaries(tx)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/live-queries/{id}",
      tags: ["Devices"],
      summary: "A live query's results, per device and as one table",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(LiveQueryDetail), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:query");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const [summary] = await summaries(tx, [id]);
        if (!summary) throw notFound("Live query");
        // Expire what the devices didn't pick up in time.
        await tx.updateTable("device_commands").set({ status: "expired", finished_at: new Date() }).where("query_id", "=", id).where("status", "in", ["queued", "sent"]).where("expires_at", "<", new Date()).execute();
        const cmds = await tx
          .selectFrom("device_commands")
          .innerJoin("devices", "devices.id", "device_commands.device_id")
          .select(["device_commands.device_id", "devices.hostname", "device_commands.status", "device_commands.output", "device_commands.result", "device_commands.finished_at"])
          .where("device_commands.query_id", "=", id)
          .orderBy("devices.hostname")
          .execute();
        const columns = new Set<string>();
        const rows: Record<string, string>[] = [];
        const results = cmds.map((r) => {
          const res = QueryResult.safeParse(r.result).data;
          for (const row of res?.rows ?? []) {
            if (rows.length >= 10_000) break;
            for (const k of Object.keys(row)) columns.add(k);
            rows.push({ _device: r.hostname, ...row });
          }
          return { device_id: r.device_id, hostname: r.hostname, status: r.status, message: r.status === "done" ? "" : r.output, rows: res?.rows.length ?? 0, truncated: !!res?.truncated, finished_at: isoOrNull(r.finished_at) };
        });
        return { ...(await summaries(tx, [id]))[0]!, results, columns: [...columns], rows };
      });
      return c.json(out, 200);
    },
  );
}

async function auditLiveQuery(tx: Tx, p: { orgId: string; userId: string } & Record<string, unknown>, meta: RequestMeta, q: { id: string; sql: string; reason: string; target: unknown; devices: number; skipped: number }) {
  await audit(tx, p.orgId, { principal: p as never, meta }, {
    type: "device.live_query",
    target: { type: "live_query", id: q.id, display: q.sql.slice(0, 120) },
    details: { sql: q.sql, reason: q.reason, target: q.target, devices: q.devices, skipped_without_osquery: q.skipped },
  });
}

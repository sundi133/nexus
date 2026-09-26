import { randomBytes } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { toAuditEvent } from "../audit/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { AuditEvent, bearer, body, Id, iso, json, patchOf, problemResponses, Timestamp } from "../schemas.js";
import { ensureBuiltins, SEVERITIES } from "./engine.js";
import { hashToken, oncallAad, queuePage, send } from "./oncall.js";

/** Alert triage, alert rules and on-call integrations (SPEC AUD-08, OPS-08, NTF-10). */

const Severity = z.enum(SEVERITIES);
const Resolution = z.enum(["true_positive", "false_positive", "benign"]);

const AlertOut = z
  .object({
    id: Id,
    title: z.string(),
    rule: z.object({ id: Id.nullable(), name: z.string() }),
    subject: z.string(),
    severity: Severity,
    status: z.enum(["open", "acknowledged", "resolved"]),
    snoozed_until: Timestamp.nullable(),
    count: z.number().int(),
    first_seen_at: Timestamp,
    last_seen_at: Timestamp,
    assignee: z.object({ id: Id, name: z.string() }).nullable(),
    acknowledged_by: z.string(),
    acknowledged_at: Timestamp.nullable(),
    resolved_by: z.string(),
    resolved_at: Timestamp.nullable(),
    resolution: z.enum(["", "true_positive", "false_positive", "benign"]),
    paged: z.number().int().openapi({ description: "On-call integrations it was sent to" }),
  })
  .openapi("Alert");

const alertQuery = (tx: Tx) =>
  tx
    .selectFrom("alerts")
    .leftJoin("users as a", "a.id", "alerts.assignee_id")
    .selectAll("alerts")
    .select(["a.given_name as a_given", "a.family_name as a_family", "a.email as a_email"]);
type AlertRow = Awaited<ReturnType<ReturnType<typeof alertQuery>["executeTakeFirstOrThrow"]>>;

const toAlert = (a: AlertRow): z.infer<typeof AlertOut> => ({
  id: a.id,
  title: a.title,
  rule: { id: a.rule_id, name: a.rule_name },
  subject: a.subject,
  severity: a.severity,
  status: a.status,
  snoozed_until: a.snoozed_until && a.snoozed_until > new Date() ? iso(a.snoozed_until) : null,
  count: a.count,
  first_seen_at: iso(a.first_seen_at),
  last_seen_at: iso(a.last_seen_at),
  assignee: a.assignee_id ? { id: a.assignee_id, name: `${a.a_given ?? ""} ${a.a_family ?? ""}`.trim() || (a.a_email ?? "") } : null,
  acknowledged_by: a.acknowledged_by,
  acknowledged_at: a.acknowledged_at ? iso(a.acknowledged_at) : null,
  resolved_by: a.resolved_by,
  resolved_at: a.resolved_at ? iso(a.resolved_at) : null,
  resolution: a.resolution,
  paged: ((a.paged as unknown as string[]) ?? []).length,
});

const MatchSchema = z
  .object({
    types: z.array(z.string().regex(/^[a-z_]+(\.[a-z_]+)?\*?$|^[a-z_]+\.\*$/, "An event type like auth.login, or a prefix like mcp.*")).min(1).max(20),
    outcome: z.enum(["success", "failure", "denied"]).optional(),
    details: z.record(z.string().max(50), z.string().max(200)).optional(),
  })
  .openapi("AlertMatch");

const RuleInput = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().trim().max(500).default(""),
  enabled: z.boolean().default(true),
  severity: Severity,
  match: MatchSchema,
  group_by: z.enum(["none", "actor", "target", "ip"]).default("none"),
  threshold: z.number().int().min(1).max(10000).default(1),
  window_minutes: z.number().int().min(1).max(1440).default(5),
});

const RuleOut = z
  .object({
    id: Id,
    builtin: z.boolean(),
    name: z.string(),
    description: z.string(),
    enabled: z.boolean(),
    severity: Severity,
    match: MatchSchema,
    group_by: z.enum(["none", "actor", "target", "ip"]),
    threshold: z.number().int(),
    window_minutes: z.number().int(),
    quality: z
      .object({
        fired_30d: z.number().int(),
        open: z.number().int(),
        false_positive_rate: z.number().nullable().openapi({ description: "Of alerts resolved with a verdict in 30 days" }),
        median_minutes_to_ack: z.number().nullable(),
      })
      .openapi({ description: "Alert quality: rules that fire a lot and get dismissed are noise" }),
  })
  .openapi("AlertRule");

const IntegrationOut = z
  .object({ id: Id, kind: z.enum(["pagerduty", "opsgenie"]), name: z.string(), region: z.enum(["us", "eu"]), min_severity: Severity, enabled: z.boolean(), last_error: z.string(), last_sent_at: Timestamp.nullable(), created_at: Timestamp })
  .openapi("OncallIntegration");

async function getAlert(tx: Tx, id: string) {
  const a = await alertQuery(tx).where("alerts.id", "=", id).executeTakeFirst();
  if (!a) throw notFound("Alert");
  return a;
}

/** Acknowledge or resolve, from Nexus or from the on-call tool. */
export async function transition(tx: Tx, orgId: string, a: { id: string; status: string; title: string }, to: "acknowledged" | "resolved", who: { display: string; meta: RequestMeta; principal?: Parameters<typeof audit>[2]["principal"]; fromIntegration?: string }, extra: { resolution?: z.infer<typeof Resolution> } = {}) {
  if (a.status === "resolved" || (to === "acknowledged" && a.status === "acknowledged")) return false;
  const now = new Date();
  await tx
    .updateTable("alerts")
    .set(to === "acknowledged" ? { status: "acknowledged", acknowledged_by: who.display, acknowledged_at: now } : { status: "resolved", resolved_by: who.display, resolved_at: now, resolution: extra.resolution ?? "", ...(a.status === "open" ? { acknowledged_by: who.display, acknowledged_at: now } : {}) })
    .where("id", "=", a.id)
    .execute();
  await audit(tx, orgId, { principal: who.principal, meta: who.meta }, {
    type: to === "acknowledged" ? "alert.acknowledged" : "alert.resolved",
    ...(who.principal ? {} : { actor: { type: "system" as const, id: null, display: who.display } }),
    target: { type: "alert", id: a.id, display: a.title },
    details: { ...extra, ...(who.fromIntegration ? { via: who.fromIntegration } : {}) },
  });
  await queuePage(tx, orgId, a.id, to === "acknowledged" ? "acknowledge" : "resolve", who.fromIntegration);
  return true;
}

async function ruleQuality(tx: Tx) {
  const rows = await sql<{ rule_id: string; fired: number; open: number; fp: number; judged: number; ack_min: number | null }>`
    SELECT rule_id,
      count(*) FILTER (WHERE created_at > now() - interval '30 days')::int AS fired,
      count(*) FILTER (WHERE status <> 'resolved')::int AS open,
      count(*) FILTER (WHERE resolution = 'false_positive' AND resolved_at > now() - interval '30 days')::int AS fp,
      count(*) FILTER (WHERE resolution <> '' AND resolved_at > now() - interval '30 days')::int AS judged,
      percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM acknowledged_at - created_at) / 60) FILTER (WHERE acknowledged_at IS NOT NULL) AS ack_min
    FROM alerts WHERE rule_id IS NOT NULL GROUP BY rule_id`.execute(tx);
  return new Map(rows.rows.map((r) => [r.rule_id, { fired_30d: r.fired, open: r.open, false_positive_rate: r.judged ? r.fp / r.judged : null, median_minutes_to_ack: r.ack_min === null ? null : Math.round(Number(r.ack_min) * 10) / 10 }]));
}

export function registerAlertRoutes(app: App) {
  const stepUp = async (c: Parameters<typeof requireRecentMfa>[0], tx: Tx, p: Parameters<typeof requireRecentMfa>[1]) => requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
  const actorName = (p: { email?: string; apiKey?: unknown }) => p.email ?? "API key";

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/alerts",
      tags: ["Alerts"],
      summary: "List alerts",
      description: "`active` (the default) is open and acknowledged alerts that aren't snoozed, most severe and most recent first.",
      security: bearer,
      request: { query: z.object({ status: z.enum(["active", "open", "acknowledged", "resolved", "snoozed", "all"]).default("active"), severity: Severity.optional(), limit: z.coerce.number().int().min(1).max(200).default(100) }) },
      responses: { 200: json(z.object({ data: z.array(AlertOut), counts: z.object({ open: z.number().int(), acknowledged: z.number().int(), snoozed: z.number().int() }) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "alerts:read");
      const q = c.req.valid("query");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const now = new Date();
        let query = alertQuery(tx);
        if (q.status === "active") query = query.where("alerts.status", "<>", "resolved").where((eb) => eb.or([eb("alerts.snoozed_until", "is", null), eb("alerts.snoozed_until", "<=", now)]));
        else if (q.status === "snoozed") query = query.where("alerts.status", "<>", "resolved").where("alerts.snoozed_until", ">", now);
        else if (q.status !== "all") query = query.where("alerts.status", "=", q.status);
        if (q.severity) query = query.where("alerts.severity", "=", q.severity);
        const rows = await query
          .orderBy(sql`array_position(ARRAY['critical','high','medium','low'], alerts.severity)`)
          .orderBy("alerts.last_seen_at", "desc")
          .limit(q.limit)
          .execute();
        const counts = (
          await sql<{ open: number; acknowledged: number; snoozed: number }>`
            SELECT count(*) FILTER (WHERE status = 'open' AND (snoozed_until IS NULL OR snoozed_until <= now()))::int AS open,
                   count(*) FILTER (WHERE status = 'acknowledged' AND (snoozed_until IS NULL OR snoozed_until <= now()))::int AS acknowledged,
                   count(*) FILTER (WHERE status <> 'resolved' AND snoozed_until > now())::int AS snoozed
            FROM alerts`.execute(tx)
        ).rows[0]!;
        return { data: rows.map(toAlert), counts };
      });
      return c.json(out, 200);
    },
  );

  const Detail = z.object({ alert: AlertOut, rule_description: z.string(), events: z.array(AuditEvent), notes: z.array(z.object({ id: Id, author: z.string(), body: z.string(), at: Timestamp })) });
  const detail = async (tx: Tx, id: string): Promise<z.infer<typeof Detail>> => {
    const a = await getAlert(tx, id);
    const rule = a.rule_id ? await tx.selectFrom("alert_rules").select("description").where("id", "=", a.rule_id).executeTakeFirst() : undefined;
    const events = a.event_ids.length ? await tx.selectFrom("audit_events").selectAll().where("id", "in", a.event_ids).orderBy("id", "desc").execute() : [];
    const notes = await tx.selectFrom("alert_notes").selectAll().where("alert_id", "=", id).orderBy("at").execute();
    return { alert: toAlert(a), rule_description: rule?.description ?? "", events: events.map(toAuditEvent), notes: notes.map((n) => ({ id: n.id, author: n.author, body: n.body, at: iso(n.at) })) };
  };

  app.openapi(
    createRoute({ method: "get", path: "/v1/alerts/{id}", tags: ["Alerts"], summary: "Get an alert with its events and notes", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(Detail), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "alerts:read");
      return c.json(await c.get("deps").db.tenant(p.orgId, (tx) => detail(tx, c.req.valid("param").id)), 200);
    },
  );

  const Action = z.discriminatedUnion("action", [
    z.object({ action: z.literal("acknowledge") }),
    z.object({ action: z.literal("resolve"), resolution: Resolution, note: z.string().trim().max(2000).optional() }),
    z.object({ action: z.literal("snooze"), minutes: z.number().int().min(5).max(7 * 24 * 60) }),
    z.object({ action: z.literal("unsnooze") }),
    z.object({ action: z.literal("assign"), user_id: Id.nullable() }),
    z.object({ action: z.literal("note"), body: z.string().trim().min(1).max(2000) }),
  ]);

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/alerts/{id}/actions",
      tags: ["Alerts"],
      summary: "Triage an alert",
      description: "Acknowledge, resolve with a verdict (which feeds the rule's quality), snooze, assign, or add a note. Acknowledging and resolving also update PagerDuty or Opsgenie.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(Action) },
      responses: { 200: json(Detail), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "alerts:triage");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const meta = c.get("meta");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await getAlert(tx, id);
        const who = { display: actorName(p), meta, principal: p };
        switch (input.action) {
          case "acknowledge":
            if (a.status !== "open") throw conflict("not_open", a.status === "resolved" ? "This alert is resolved" : "Already acknowledged");
            await transition(tx, p.orgId, a, "acknowledged", who);
            break;
          case "resolve":
            if (a.status === "resolved") throw conflict("resolved", "This alert is already resolved");
            if (input.note) await tx.insertInto("alert_notes").values({ id: newId(), org_id: p.orgId, alert_id: id, author_id: p.apiKey ? null : p.userId, author: actorName(p), body: input.note }).execute();
            await transition(tx, p.orgId, a, "resolved", who, { resolution: input.resolution });
            break;
          case "snooze":
          case "unsnooze": {
            if (a.status === "resolved") throw conflict("resolved", "This alert is resolved");
            const until = input.action === "snooze" ? new Date(Date.now() + input.minutes * 60_000) : null;
            await tx.updateTable("alerts").set({ snoozed_until: until }).where("id", "=", id).execute();
            await audit(tx, p.orgId, { principal: p, meta }, { type: input.action === "snooze" ? "alert.snoozed" : "alert.unsnoozed", target: { type: "alert", id, display: a.title }, details: until ? { until: until.toISOString() } : {} });
            break;
          }
          case "assign":
            if (input.user_id && !(await tx.selectFrom("users").select("id").where("id", "=", input.user_id).where("status", "=", "active").executeTakeFirst())) throw notFound("User");
            await tx.updateTable("alerts").set({ assignee_id: input.user_id }).where("id", "=", id).execute();
            await audit(tx, p.orgId, { principal: p, meta }, { type: "alert.assigned", target: { type: "alert", id, display: a.title }, details: { user_id: input.user_id } });
            break;
          case "note":
            await tx.insertInto("alert_notes").values({ id: newId(), org_id: p.orgId, alert_id: id, author_id: p.apiKey ? null : p.userId, author: actorName(p), body: input.body }).execute();
            break;
        }
        return detail(tx, id);
      });
      return c.json(out, 200);
    },
  );

  // ---- Rules ----

  const rulesOut = async (tx: Tx, orgId: string) => {
    await ensureBuiltins(tx, orgId);
    const rows = await tx.selectFrom("alert_rules").selectAll().orderBy("builtin_key", "asc").orderBy("name").execute();
    const q = await ruleQuality(tx);
    return rows.map((r) => ({
      id: r.id,
      builtin: !!r.builtin_key,
      name: r.name,
      description: r.description,
      enabled: r.enabled,
      severity: r.severity,
      match: r.match as unknown as z.infer<typeof MatchSchema>,
      group_by: r.group_by,
      threshold: r.threshold,
      window_minutes: r.window_minutes,
      quality: q.get(r.id) ?? { fired_30d: 0, open: 0, false_positive_rate: null, median_minutes_to_ack: null },
    }));
  };

  app.openapi(
    createRoute({ method: "get", path: "/v1/alert-rules", tags: ["Alerts"], summary: "List alert rules, with their quality", security: bearer, responses: { 200: json(z.object({ data: z.array(RuleOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "alerts:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => rulesOut(tx, p.orgId)) }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/alert-rules", tags: ["Alerts"], summary: "Add an alert rule", security: bearer, request: body(RuleInput), responses: { 201: json(z.object({ data: z.array(RuleOut) }), "Created"), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "alerts:manage");
      const input = c.req.valid("json");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const id = newId();
        await tx.insertInto("alert_rules").values({ id, org_id: p.orgId, ...input, match: JSON.stringify(input.match), created_by: p.apiKey ? null : p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "alert.rule_created", target: { type: "alert_rule", id, display: input.name }, details: { ...input } });
        return rulesOut(tx, p.orgId);
      });
      return c.json({ data }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/alert-rules/{id}",
      tags: ["Alerts"],
      summary: "Change an alert rule",
      description: "Default rules can be tuned (threshold, window, severity) or turned off, not deleted.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(patchOf(RuleInput)) },
      responses: { 200: json(z.object({ data: z.array(RuleOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "alerts:manage");
      const { id } = c.req.valid("param");
      const patch = c.req.valid("json");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.selectFrom("alert_rules").selectAll().where("id", "=", id).executeTakeFirst();
        if (!r) throw notFound("Rule");
        const { match, ...rest } = patch;
        await tx.updateTable("alert_rules").set({ ...rest, ...(match ? { match: JSON.stringify(match) } : {}), updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "alert.rule_changed", target: { type: "alert_rule", id, display: r.name }, details: { changes: patch } });
        return rulesOut(tx, p.orgId);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/alert-rules/{id}", tags: ["Alerts"], summary: "Delete an alert rule", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Deleted" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "alerts:manage");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.selectFrom("alert_rules").selectAll().where("id", "=", id).executeTakeFirst();
        if (!r) throw notFound("Rule");
        if (r.builtin_key) throw conflict("builtin", "Default rules can be turned off but not deleted");
        await tx.deleteFrom("alert_rules").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "alert.rule_deleted", target: { type: "alert_rule", id, display: r.name } });
      });
      return c.body(null, 204);
    },
  );

  // ---- On-call ----

  const IntegrationInput = z.object({
    kind: z.enum(["pagerduty", "opsgenie"]),
    name: z.string().trim().min(1).max(100),
    key: z.string().trim().min(8).max(200).openapi({ description: "PagerDuty: an Events API v2 integration (routing) key. Opsgenie: an API integration key." }),
    region: z.enum(["us", "eu"]).default("us").openapi({ description: "Opsgenie only" }),
    min_severity: Severity.default("critical"),
  });
  const listIntegrations = async (tx: Tx) =>
    (await tx.selectFrom("oncall_integrations").selectAll().orderBy("created_at").execute()).map((i) => ({ id: i.id, kind: i.kind, name: i.name, region: i.region, min_severity: i.min_severity, enabled: i.enabled, last_error: i.last_error, last_sent_at: i.last_sent_at ? iso(i.last_sent_at) : null, created_at: iso(i.created_at) }));

  app.openapi(
    createRoute({ method: "get", path: "/v1/oncall-integrations", tags: ["Alerts"], summary: "List on-call integrations", security: bearer, responses: { 200: json(z.object({ data: z.array(IntegrationOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "alerts:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, listIntegrations) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/oncall-integrations",
      tags: ["Alerts"],
      summary: "Connect PagerDuty or Opsgenie",
      description: "Returns a webhook URL, once: point the tool's webhook (PagerDuty v3 webhook subscription, or Opsgenie outgoing webhook) at it, so acknowledging or resolving there does the same in Nexus.",
      security: bearer,
      request: body(IntegrationInput),
      responses: { 201: json(z.object({ integration: IntegrationOut, webhook_url: z.string() }), "Connected"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "alerts:manage");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      const id = newId();
      const token = `nxoc_${randomBytes(24).toString("base64url")}`;
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        await tx
          .insertInto("oncall_integrations")
          .values({ id, org_id: p.orgId, kind: input.kind, name: input.name, secret: deps.sealer.seal(Buffer.from(input.key), oncallAad(id)), region: input.region, min_severity: input.min_severity, inbound_hash: hashToken(token), created_by: p.apiKey ? null : p.userId })
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "alert.oncall_connected", target: { type: "oncall_integration", id, display: input.name }, details: { kind: input.kind, min_severity: input.min_severity } });
        return (await listIntegrations(tx)).find((i) => i.id === id)!;
      });
      return c.json({ integration: out, webhook_url: `${deps.cfg.apiPublicUrl}/hooks/oncall/${token}` }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/oncall-integrations/{id}",
      tags: ["Alerts"],
      summary: "Change an on-call integration",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ name: z.string().trim().min(1).max(100).optional(), min_severity: Severity.optional(), enabled: z.boolean().optional() })) },
      responses: { 200: json(z.object({ data: z.array(IntegrationOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "alerts:manage");
      const { id } = c.req.valid("param");
      const patch = c.req.valid("json");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.updateTable("oncall_integrations").set(patch).where("id", "=", id).executeTakeFirst();
        if (!Number(r.numUpdatedRows)) throw notFound("Integration");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "alert.oncall_changed", target: { type: "oncall_integration", id }, details: { changes: patch } });
        return listIntegrations(tx);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/oncall-integrations/{id}", tags: ["Alerts"], summary: "Disconnect an on-call integration", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Disconnected" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "alerts:manage");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.deleteFrom("oncall_integrations").where("id", "=", id).executeTakeFirst();
        if (!Number(r.numDeletedRows)) throw notFound("Integration");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "alert.oncall_disconnected", target: { type: "oncall_integration", id } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/oncall-integrations/{id}/test",
      tags: ["Alerts"],
      summary: "Send a test page",
      description: "Triggers a test incident and resolves it right away.",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ ok: z.boolean(), error: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "alerts:manage");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const i = await deps.db.tenant(p.orgId, (tx) => tx.selectFrom("oncall_integrations").selectAll().where("id", "=", id).executeTakeFirst());
      if (!i) throw notFound("Integration");
      const fake = { id: newId(), title: "Test page from Votal Nexus", severity: "critical" as const, rule_name: "Test", subject: actorName(p), count: 1, first_seen_at: new Date() };
      try {
        await send(deps, i, fake, "trigger", `${deps.cfg.publicUrl}/alerts`);
        await send(deps, i, fake, "resolve", `${deps.cfg.publicUrl}/alerts`);
        await deps.db.tenant(p.orgId, (tx) => tx.updateTable("oncall_integrations").set({ last_error: "", last_sent_at: new Date() }).where("id", "=", id).execute());
        return c.json({ ok: true, error: "" }, 200);
      } catch (e) {
        return c.json({ ok: false, error: (e as Error).message }, 200);
      }
    },
  );

  registerOncallWebhook(app);
}

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

/**
 * Acknowledgements back from PagerDuty (v3 webhooks: incident.acknowledged,
 * incident.resolved) and Opsgenie (outgoing webhook: Acknowledge, Close). The
 * URL carries a per-integration secret; the alert is found by the dedup key /
 * alias Nexus sent, which is the alert's ID.
 */
function registerOncallWebhook(app: App) {
  app.post("/hooks/oncall/:token", async (c) => {
    const deps: Deps = c.get("deps");
    const found = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; integration_id: string }>`SELECT * FROM nexus_oncall_by_token(${hashToken(c.req.param("token"))})`.execute(tx)).rows[0]);
    if (!found) return c.json({ error: "not_found" }, 404);
    const text = (await c.req.text()).slice(0, 256 * 1024);
    let payload: Record<string, any>;
    try {
      payload = JSON.parse(text);
    } catch {
      return c.json({ error: "invalid_json" }, 400);
    }
    let to: "acknowledged" | "resolved" | null = null;
    let keys: string[] = [];
    const pd = payload.event as { event_type?: string; data?: Record<string, any> } | undefined;
    if (pd?.event_type) {
      to = pd.event_type === "incident.acknowledged" ? "acknowledged" : pd.event_type === "incident.resolved" ? "resolved" : null;
      keys = [pd.data?.incident_key, ...(JSON.stringify(pd.data ?? {}).match(UUID) ?? [])].filter(Boolean);
    } else if (payload.action) {
      to = payload.action === "Acknowledge" ? "acknowledged" : payload.action === "Close" ? "resolved" : null;
      keys = [payload.alert?.alias].filter(Boolean);
    }
    if (!to || !keys.length) return c.json({ ok: true, ignored: true });
    const done = await deps.db.tenant(found.org_id, async (tx) => {
      const i = await tx.selectFrom("oncall_integrations").select(["name", "kind"]).where("id", "=", found.integration_id).executeTakeFirstOrThrow();
      const alert = await tx.selectFrom("alerts").select(["id", "status", "title"]).where("id", "in", [...new Set(keys.map((k) => String(k).toLowerCase()))].filter((k) => /^[0-9a-f-]{36}$/.test(k))).executeTakeFirst();
      if (!alert) return false;
      const who = payload.event?.agent?.summary ?? payload.alert?.username ?? "";
      return transition(tx, found.org_id, alert, to!, { display: `${i.name}${who ? ` (${who})` : ""}`, meta: c.get("meta"), fromIntegration: found.integration_id });
    });
    return c.json({ ok: true, updated: done });
  });
}

import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { sql } from "kysely";
import { randomBytes } from "node:crypto";
import type { App, Env, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { isUniqueViolation, type Tx } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { assertSafeUrl, UnsafeUrlError } from "../platform/outbound.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { formatEvent } from "./formats.js";
import { send } from "./senders.js";
import { secretAad } from "./stream.js";

const Kind = z.enum(["webhook", "splunk_hec", "datadog"]);
const Format = z.enum(["nexus", "ocsf"]);
const Filter = z.array(z.string().regex(/^[a-z_]+(\.[a-z_]*|\*)?$/, "An event type or prefix like user. or auth*")).max(50);
const Config = z.object({ index: z.string().max(100).optional(), sourcetype: z.string().max(100).optional(), tags: z.string().max(500).optional(), service: z.string().max(100).optional() });

const Destination = z
  .object({
    id: Id,
    kind: Kind,
    name: z.string(),
    url: z.string(),
    format: Format,
    event_filter: z.array(z.string()),
    config: Config,
    enabled: z.boolean(),
    status: z.enum(["healthy", "failing", "off", "waiting"]),
    backlog: z.number().int().openapi({ description: "Events not yet delivered (capped at 10,000)" }),
    last_delivered_at: z.string().nullable(),
    last_error: z.string(),
    consecutive_failures: z.number().int(),
    disabled_reason: z.string(),
    created_at: z.string(),
  })
  .openapi("EventDestination");
const Delivery = z.object({ at: z.string(), ok: z.boolean(), http_status: z.number().int(), events: z.number().int(), duration_ms: z.number().int(), error: z.string() }).openapi("EventDelivery");

async function list(tx: Tx): Promise<z.infer<typeof Destination>[]> {
  const rows = await tx.selectFrom("event_destinations").selectAll().orderBy("created_at").execute();
  const out: z.infer<typeof Destination>[] = [];
  for (const d of rows) {
    const backlog = await sql<{ n: number }>`
      SELECT count(*)::int AS n FROM (SELECT 1 FROM audit_events WHERE (txid, id) > (${d.cursor_txid}::xid8, ${d.cursor_id}::uuid) LIMIT 10000) x`.execute(tx);
    out.push({
      id: d.id,
      kind: d.kind,
      name: d.name,
      url: d.url,
      format: d.format,
      event_filter: d.event_filter,
      config: d.config as z.infer<typeof Config>,
      enabled: d.enabled,
      status: !d.enabled ? "off" : d.consecutive_failures > 0 ? "failing" : d.last_delivered_at ? "healthy" : "waiting",
      backlog: backlog.rows[0]!.n,
      last_delivered_at: d.last_delivered_at ? iso(d.last_delivered_at) : null,
      last_error: d.last_error,
      consecutive_failures: d.consecutive_failures,
      disabled_reason: d.disabled_reason,
      created_at: iso(d.created_at),
    });
  }
  return out;
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

async function checkedUrl(c: Context<Env>, url: string) {
  try {
    return (await assertSafeUrl(url, { allowPrivate: c.get("deps").cfg.allowPrivateOutbound })).toString();
  } catch (err) {
    if (err instanceof UnsafeUrlError) throw badRequest("unsafe_url", err.message);
    throw err;
  }
}

export function registerEventDestinationRoutes(app: App) {
  const listResponse = { 200: json(z.object({ data: z.array(Destination) })), ...problemResponses };
  const idParam = { params: z.object({ id: Id }) };

  app.openapi(
    createRoute({ method: "get", path: "/v1/event-destinations", tags: ["Integrations"], summary: "Webhooks and SIEM streams", security: bearer, responses: listResponse }),
    async (c) => {
      const p = requirePermission(c, "integrations:manage");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, list) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/event-destinations",
      tags: ["Integrations"],
      summary: "Stream audit events to a webhook, Splunk or Datadog (requires recent MFA)",
      description: "Webhooks get a generated signing secret, returned once. `start: last_24h` backfills the last day.",
      security: bearer,
      request: body(
        z.object({
          kind: Kind,
          name: z.string().trim().min(1).max(100),
          url: z.string().max(1000),
          secret: z.string().min(1).max(1000).optional().openapi({ description: "Splunk HEC token or Datadog API key. Webhooks: leave empty to generate one." }),
          format: Format.default("nexus"),
          event_filter: Filter.default([]),
          config: Config.default({}),
          start: z.enum(["now", "last_24h"]).default("now"),
        }),
      ),
      responses: { 201: json(z.object({ data: z.array(Destination), signing_secret: z.string().nullable() }), "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "integrations:manage");
      const input = c.req.valid("json");
      if (input.kind !== "webhook" && !input.secret) throw badRequest("secret_required", input.kind === "splunk_hec" ? "A Splunk HEC token is required" : "A Datadog API key is required");
      const url = await checkedUrl(c, input.url);
      const secret = input.secret ?? `whsec_${randomBytes(24).toString("base64url")}`;
      const id = newId();
      const deps = c.get("deps");
      try {
        const data = await deps.db.tenant(p.orgId, async (tx) => {
          await stepUp(c, tx, p);
          // Start just after "now" (this transaction), or just before the first event of the last day.
          const start =
            input.start === "last_24h"
              ? (await sql<{ t: string }>`SELECT ((txid::text)::bigint - 1)::text AS t FROM audit_events WHERE ts >= now() - interval '24 hours' ORDER BY txid, id LIMIT 1`.execute(tx)).rows[0]?.t
              : undefined;
          const cursor = start
            ? { cursor_txid: start, cursor_id: "ffffffff-ffff-ffff-ffff-ffffffffffff" }
            : { cursor_txid: (await sql<{ t: string }>`SELECT pg_current_xact_id()::text AS t`.execute(tx)).rows[0]!.t, cursor_id: "ffffffff-ffff-ffff-ffff-ffffffffffff" };
          await tx
            .insertInto("event_destinations")
            .values({
              id,
              org_id: p.orgId,
              kind: input.kind,
              name: input.name,
              url,
              secret: deps.sealer.seal(Buffer.from(secret), secretAad(id)),
              config: JSON.stringify(input.config),
              format: input.format,
              event_filter: input.event_filter,
              created_by: p.userId,
              ...cursor,
            })
            .execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "integration.destination_created",
            target: { type: "event_destination", id, display: input.name },
            details: { kind: input.kind, url, format: input.format, event_filter: input.event_filter, start: input.start },
          });
          return list(tx);
        });
        return c.json({ data, signing_secret: input.kind === "webhook" && !input.secret ? secret : null }, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "A destination with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/event-destinations/{id}",
      tags: ["Integrations"],
      summary: "Change or re-enable a destination (requires recent MFA)",
      description: "Turning it back on resumes where delivery stopped.",
      security: bearer,
      request: {
        ...idParam,
        ...body(z.object({ name: z.string().trim().min(1).max(100).optional(), url: z.string().max(1000).optional(), secret: z.string().min(1).max(1000).optional(), format: Format.optional(), event_filter: Filter.optional(), config: Config.optional(), enabled: z.boolean().optional() })),
      },
      responses: listResponse,
    }),
    async (c) => {
      const p = requirePermission(c, "integrations:manage");
      const { id } = c.req.valid("param");
      const { secret, url, config, enabled, ...rest } = c.req.valid("json");
      const deps = c.get("deps");
      const checked = url ? await checkedUrl(c, url) : undefined;
      const data = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const before = await tx.selectFrom("event_destinations").select(["name", "enabled"]).where("id", "=", id).executeTakeFirst();
        if (!before) throw notFound("Destination");
        await tx
          .updateTable("event_destinations")
          .set({
            ...rest,
            ...(checked ? { url: checked } : {}),
            ...(config ? { config: JSON.stringify(config) } : {}),
            ...(secret ? { secret: deps.sealer.seal(Buffer.from(secret), secretAad(id)) } : {}),
            ...(enabled !== undefined ? { enabled } : {}),
            ...(enabled && !before.enabled ? { consecutive_failures: 0, disabled_reason: "", next_attempt_at: new Date(), last_error: "" } : {}),
            updated_at: new Date(),
          })
          .where("id", "=", id)
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "integration.destination_updated",
          target: { type: "event_destination", id, display: rest.name ?? before.name },
          details: { changes: { ...rest, ...(checked ? { url: checked } : {}), ...(enabled !== undefined ? { enabled } : {}) }, secret_rotated: !!secret },
        });
        return list(tx);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/event-destinations/{id}", tags: ["Integrations"], summary: "Delete a destination (requires recent MFA)", security: bearer, request: idParam, responses: listResponse }),
    async (c) => {
      const p = requirePermission(c, "integrations:manage");
      const { id } = c.req.valid("param");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const r = await tx.deleteFrom("event_destinations").where("id", "=", id).returning("name").executeTakeFirst();
        if (!r) throw notFound("Destination");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "integration.destination_deleted", target: { type: "event_destination", id, display: r.name } });
        return list(tx);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/event-destinations/{id}/test",
      tags: ["Integrations"],
      summary: "Send a test event now",
      security: bearer,
      request: idParam,
      responses: { 200: json(z.object({ ok: z.boolean(), http_status: z.number().int(), error: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "integrations:manage");
      const deps = c.get("deps");
      const d = await deps.db.tenant(p.orgId, (tx) => tx.selectFrom("event_destinations").selectAll().where("id", "=", c.req.valid("param").id).executeTakeFirst());
      if (!d) throw notFound("Destination");
      await checkedUrl(c, d.url);
      const e = {
        id: newId(), org_id: p.orgId, ts: new Date(), type: "integration.test", outcome: "success" as const, actor_type: "user", actor_id: p.userId, actor_display: p.email,
        target_type: "event_destination", target_id: d.id, target_display: d.name, session_id: null, ip: c.get("meta").ip, user_agent: "", details: { message: "Test event from Votal Nexus" },
      };
      const r = await send(d.kind, d.url, deps.sealer.open(d.secret, secretAad(d.id)).toString(), d.config as Record<string, string>, [{ id: e.id, type: e.type, time: e.ts, body: formatEvent(d.format, e) }]);
      return c.json({ ok: !r.error, http_status: r.status, error: r.error }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/event-destinations/{id}/deliveries", tags: ["Integrations"], summary: "Recent delivery attempts", security: bearer, request: idParam, responses: { 200: json(z.object({ data: z.array(Delivery) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "integrations:manage");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx.selectFrom("event_deliveries").select(["at", "ok", "http_status", "events", "duration_ms", "error"]).where("destination_id", "=", c.req.valid("param").id).orderBy("at", "desc").limit(50).execute(),
      );
      return c.json({ data: rows.map((r) => ({ ...r, at: iso(r.at) })) }, 200);
    },
  );
}

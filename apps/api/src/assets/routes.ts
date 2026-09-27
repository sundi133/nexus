import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";

/**
 * Asset management (docs/ASSETS.md): hardware the organization owns, whether or not it runs the
 * Nexus agent. Enrolled devices are matched by serial number. Checking an asset out to someone and
 * back in keeps a history; offboarding lists what to collect.
 */

const WARRANTY_SOON_DAYS = 90;
const Kind = z.enum(["laptop", "desktop", "phone", "tablet", "monitor", "peripheral", "network", "server", "other"]);
const Status = z.enum(["in_stock", "assigned", "in_repair", "retired", "lost"]);
const Returned = z.enum(["in_stock", "in_repair", "retired", "lost"]);
const Date_ = z.iso.date().nullable();

const AssetIn = z.object({
  tag: z.string().trim().min(1).max(64),
  name: z.string().trim().max(200).default(""),
  kind: Kind.default("other"),
  make: z.string().trim().max(100).default(""),
  model: z.string().trim().max(200).default(""),
  serial: z.string().trim().max(100).default(""),
  location: z.string().trim().max(200).default(""),
  vendor: z.string().trim().max(200).default(""),
  purchase_date: Date_.default(null),
  purchase_cost: z.number().min(0).max(100_000_000).nullable().default(null),
  currency: z.string().regex(/^[A-Z]{3}$/).default("USD"),
  warranty_until: Date_.default(null),
  notes: z.string().trim().max(2000).default(""),
});

const AssetOut = z
  .object({
    id: Id,
    tag: z.string(),
    name: z.string(),
    kind: Kind,
    make: z.string(),
    model: z.string(),
    serial: z.string(),
    status: Status,
    assigned_to: z.object({ id: z.string(), email: z.string(), name: z.string(), left: z.boolean().openapi({ description: "They've been suspended or offboarded: collect it" }) }).nullable(),
    location: z.string(),
    vendor: z.string(),
    purchase_date: z.string().nullable(),
    purchase_cost: z.number().nullable(),
    currency: z.string(),
    warranty_until: z.string().nullable(),
    warranty: z.enum(["none", "active", "expiring", "expired"]),
    device: z.object({ id: z.string(), hostname: z.string(), last_seen_at: z.string().nullable() }).nullable().openapi({ description: "The enrolled device with the same serial number" }),
    notes: z.string(),
    updated_at: z.string(),
  })
  .openapi("Asset");

type AssetRow = Awaited<ReturnType<typeof rows>>[number];

function rows(tx: Tx, where: { id?: string } = {}) {
  let q = tx
    .selectFrom("assets as a")
    .leftJoin("users as u", "u.id", "a.assigned_to")
    // The enrolled device with this serial, if any (compared without case or spaces; the most recently seen wins).
    .leftJoinLateral(
      (eb) =>
        eb
          .selectFrom("devices")
          .select(["devices.id", "devices.hostname", "devices.last_seen_at"])
          .where("devices.status", "=", "active")
          .where(sql<boolean>`a.serial <> '' AND upper(replace(devices.serial, ' ', '')) = upper(replace(a.serial, ' ', ''))`)
          .orderBy(sql`devices.last_seen_at DESC NULLS LAST`)
          .limit(1)
          .as("d"),
      (j) => j.onTrue(),
    )
    .select([
      "a.id",
      "a.tag",
      "a.name",
      "a.kind",
      "a.make",
      "a.model",
      "a.serial",
      "a.status",
      "a.assigned_to",
      "u.email",
      sql<string>`coalesce(trim(u.given_name || ' ' || u.family_name), '')`.as("user_name"),
      "u.status as user_status",
      "a.location",
      "a.vendor",
      sql<string | null>`a.purchase_date::text`.as("purchase_date"),
      "a.purchase_cost_cents",
      "a.currency",
      sql<string | null>`a.warranty_until::text`.as("warranty_until"),
      "a.notes",
      "a.updated_at",
      "d.id as device_id",
      "d.hostname",
      "d.last_seen_at",
    ])
    .orderBy("a.tag");
  if (where.id) q = q.where("a.id", "=", where.id);
  return q.execute();
}

function shape(r: AssetRow): z.infer<typeof AssetOut> {
  const days = r.warranty_until ? (new Date(`${r.warranty_until}T00:00:00Z`).getTime() - Date.now()) / 86_400_000 : null;
  return {
    id: r.id,
    tag: r.tag,
    name: r.name,
    kind: r.kind,
    make: r.make,
    model: r.model,
    serial: r.serial,
    status: r.status,
    assigned_to: r.assigned_to && r.email ? { id: r.assigned_to, email: r.email, name: r.user_name, left: r.user_status === "suspended" || r.user_status === "deprovisioned" } : null,
    location: r.location,
    vendor: r.vendor,
    purchase_date: r.purchase_date,
    purchase_cost: r.purchase_cost_cents === null ? null : Number(r.purchase_cost_cents) / 100,
    currency: r.currency,
    warranty_until: r.warranty_until,
    warranty: days === null ? "none" : days < 0 ? "expired" : days <= WARRANTY_SOON_DAYS ? "expiring" : "active",
    device: r.device_id ? { id: r.device_id, hostname: r.hostname ?? "", last_seen_at: r.last_seen_at ? iso(r.last_seen_at) : null } : null,
    notes: r.notes,
    updated_at: iso(r.updated_at),
  };
}

const values = (input: z.infer<typeof AssetIn>) => ({
  tag: input.tag,
  name: input.name,
  kind: input.kind,
  make: input.make,
  model: input.model,
  serial: input.serial,
  location: input.location,
  vendor: input.vendor,
  purchase_date: input.purchase_date,
  purchase_cost_cents: input.purchase_cost === null ? null : Math.round(input.purchase_cost * 100),
  currency: input.currency,
  warranty_until: input.warranty_until,
  notes: input.notes,
});

async function one(tx: Tx, id: string) {
  const [r] = await rows(tx, { id });
  if (!r) throw notFound("Asset");
  return shape(r);
}

async function tagFree(tx: Tx, tag: string, except?: string) {
  let q = tx.selectFrom("assets").select("id").where(sql`lower(tag)`, "=", tag.toLowerCase());
  if (except) q = q.where("id", "<>", except);
  if (await q.executeTakeFirst()) throw conflict("tag_taken", `Asset tag ${tag} is already in use`);
}

const KIND_FROM_PLATFORM = (model: string): z.infer<typeof Kind> => (/book|laptop|latitude|thinkpad|surface|xps|elitebook|zenbook/i.test(model) ? "laptop" : /imac|mac mini|macmini|mac studio|optiplex|desktop|tower/i.test(model) ? "desktop" : "other");

/** For offboarding: what someone has, to collect. */
export async function assetsHeldBy(tx: Tx, userId: string) {
  return tx.selectFrom("assets").select(["id", "tag", "name"]).where("assigned_to", "=", userId).where("status", "=", "assigned").orderBy("tag").execute();
}

export function registerAssetRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/assets",
      tags: ["Assets"],
      summary: "Hardware the organization owns",
      security: bearer,
      request: { query: z.object({ status: Status.optional(), kind: Kind.optional(), assigned_to: Id.optional(), q: z.string().max(100).optional() }) },
      responses: {
        200: json(
          z.object({
            data: z.array(AssetOut),
            summary: z.object({
              total: z.number().int(),
              assigned: z.number().int(),
              in_stock: z.number().int(),
              to_collect: z.number().int().openapi({ description: "Assigned to people who've left" }),
              warranty_expiring: z.number().int(),
              unenrolled_devices: z.number().int().openapi({ description: "Enrolled devices with no asset record" }),
              value: z.array(z.object({ currency: z.string(), total: z.number() })),
            }),
          }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const q = c.req.valid("query");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const all = (await rows(tx)).map(shape);
        const needle = q.q?.toLowerCase();
        const data = all.filter(
          (a) =>
            (!q.status || a.status === q.status) &&
            (!q.kind || a.kind === q.kind) &&
            (!q.assigned_to || a.assigned_to?.id === q.assigned_to) &&
            (!needle || [a.tag, a.name, a.serial, a.model, a.make, a.location, a.assigned_to?.email ?? ""].some((f) => f.toLowerCase().includes(needle))),
        );
        const unenrolled = await sql<{ n: number }>`
          SELECT count(*)::int AS n FROM devices d
          WHERE d.status = 'active' AND d.serial <> ''
            AND NOT EXISTS (SELECT 1 FROM assets a WHERE upper(replace(a.serial, ' ', '')) = upper(replace(d.serial, ' ', '')))`.execute(tx);
        const value = new Map<string, number>();
        for (const a of all) if (a.purchase_cost !== null && a.status !== "retired" && a.status !== "lost") value.set(a.currency, (value.get(a.currency) ?? 0) + a.purchase_cost);
        return {
          data,
          summary: {
            total: all.length,
            assigned: all.filter((a) => a.status === "assigned").length,
            in_stock: all.filter((a) => a.status === "in_stock").length,
            to_collect: all.filter((a) => a.status === "assigned" && a.assigned_to?.left).length,
            warranty_expiring: all.filter((a) => a.warranty === "expiring" && a.status !== "retired").length,
            unenrolled_devices: unenrolled.rows[0]?.n ?? 0,
            value: [...value].map(([currency, total]) => ({ currency, total: Math.round(total * 100) / 100 })),
          },
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/assets/{id}",
      tags: ["Assets"],
      summary: "An asset and its history",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: {
        200: json(z.object({ asset: AssetOut, history: z.array(z.object({ at: z.string(), kind: z.string(), user: z.string().nullable(), status: z.string(), note: z.string(), by: z.string().nullable() })) })),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const asset = await one(tx, id);
        const history = await tx
          .selectFrom("asset_events as e")
          .leftJoin("users as u", "u.id", "e.user_id")
          .leftJoin("users as b", "b.id", "e.actor_id")
          .select(["e.at", "e.kind", "u.email as user", "e.status", "e.note", "b.email as by"])
          .where("e.asset_id", "=", id)
          .orderBy("e.at", "desc")
          .limit(200)
          .execute();
        return { asset, history: history.map((h) => ({ ...h, at: iso(h.at) })) };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/assets", tags: ["Assets"], summary: "Add an asset", security: bearer, request: body(AssetIn), responses: { 201: json(AssetOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await tagFree(tx, input.tag);
        const id = newId();
        await tx.insertInto("assets").values({ id, org_id: p.orgId, ...values(input) }).execute();
        await tx.insertInto("asset_events").values({ id: newId(), org_id: p.orgId, asset_id: id, kind: "created", status: "in_stock", actor_id: p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "asset.created", target: { type: "asset", id, display: input.tag }, details: { kind: input.kind, serial: input.serial } });
        return one(tx, id);
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "put", path: "/v1/assets/{id}", tags: ["Assets"], summary: "Change an asset's details", security: bearer, request: { params: z.object({ id: Id }), ...body(AssetIn) }, responses: { 200: json(AssetOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await one(tx, id);
        await tagFree(tx, input.tag, id);
        await tx.updateTable("assets").set({ ...values(input), updated_at: new Date() }).where("id", "=", id).execute();
        await tx.insertInto("asset_events").values({ id: newId(), org_id: p.orgId, asset_id: id, kind: "updated", actor_id: p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "asset.updated", target: { type: "asset", id, display: input.tag } });
        return one(tx, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/assets/{id}", tags: ["Assets"], summary: "Delete an asset record (to keep its history, retire it instead)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Deleted" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await one(tx, id);
        await tx.deleteFrom("assets").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "asset.deleted", target: { type: "asset", id, display: a.tag } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/assets/{id}/checkout",
      tags: ["Assets"],
      summary: "Give an asset to someone",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ user_id: Id, note: z.string().trim().max(500).default("") })) },
      responses: { 200: json(AssetOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await one(tx, id);
        if (a.status === "assigned") throw conflict("already_assigned", `${a.tag} is with ${a.assigned_to?.email ?? "someone"}: check it in first`);
        if (a.status === "retired" || a.status === "lost") throw conflict("not_available", `${a.tag} is ${a.status}`);
        const u = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", input.user_id).executeTakeFirst();
        if (!u) throw badRequest("unknown_user", "No such person");
        await tx.updateTable("assets").set({ status: "assigned", assigned_to: input.user_id, updated_at: new Date() }).where("id", "=", id).execute();
        await tx.insertInto("asset_events").values({ id: newId(), org_id: p.orgId, asset_id: id, kind: "checked_out", user_id: input.user_id, status: "assigned", note: input.note, actor_id: p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "asset.checked_out", target: { type: "asset", id, display: a.tag }, details: { to: u.email, note: input.note } });
        return one(tx, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/assets/{id}/checkin",
      tags: ["Assets"],
      summary: "Take an asset back (to stock, repair, retirement, or report it lost)",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ status: Returned.default("in_stock"), note: z.string().trim().max(500).default("") })) },
      responses: { 200: json(AssetOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const a = await one(tx, id);
        await tx.updateTable("assets").set({ status: input.status, assigned_to: null, updated_at: new Date() }).where("id", "=", id).execute();
        await tx.insertInto("asset_events").values({ id: newId(), org_id: p.orgId, asset_id: id, kind: "checked_in", user_id: a.assigned_to?.id ?? null, status: input.status, note: input.note, actor_id: p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "asset.checked_in", target: { type: "asset", id, display: a.tag }, details: { from: a.assigned_to?.email ?? null, status: input.status, note: input.note } });
        return one(tx, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/assets/import",
      tags: ["Assets"],
      summary: "Import assets (from a spreadsheet): new tags are added, existing tags updated",
      description: "Rows may name the holder by `assigned_to_email`; an asset given a holder is marked assigned.",
      security: bearer,
      request: body(z.object({ rows: z.array(AssetIn.extend({ assigned_to_email: z.string().trim().toLowerCase().max(320).default("") })).min(1).max(5000) })),
      responses: { 200: json(z.object({ created: z.number().int(), updated: z.number().int(), errors: z.array(z.object({ row: z.number().int(), message: z.string() })) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { rows: input } = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const existing = new Map((await tx.selectFrom("assets").select(["id", "tag"]).execute()).map((a) => [a.tag.toLowerCase(), a.id]));
        const users = new Map((await tx.selectFrom("users").select(["id", sql<string>`lower(email)`.as("email")]).execute()).map((u) => [u.email, u.id]));
        const seen = new Set<string>();
        let created = 0;
        let updated = 0;
        const errors: { row: number; message: string }[] = [];
        for (const [i, r] of input.entries()) {
          const key = r.tag.toLowerCase();
          if (seen.has(key)) {
            errors.push({ row: i + 1, message: `Tag ${r.tag} appears twice` });
            continue;
          }
          seen.add(key);
          const holder = r.assigned_to_email ? users.get(r.assigned_to_email) : undefined;
          if (r.assigned_to_email && !holder) errors.push({ row: i + 1, message: `${r.assigned_to_email} isn't in Nexus: imported unassigned` });
          const assignment = holder ? { status: "assigned" as const, assigned_to: holder } : {};
          const id = existing.get(key);
          if (id) {
            await tx.updateTable("assets").set({ ...values(r), ...assignment, updated_at: new Date() }).where("id", "=", id).execute();
            updated++;
          } else {
            const nid = newId();
            await tx.insertInto("assets").values({ id: nid, org_id: p.orgId, ...values(r), ...assignment }).execute();
            await tx.insertInto("asset_events").values({ id: newId(), org_id: p.orgId, asset_id: nid, kind: holder ? "checked_out" : "created", user_id: holder ?? null, status: holder ? "assigned" : "in_stock", note: "Imported", actor_id: p.userId }).execute();
            created++;
          }
        }
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "asset.imported", details: { created, updated, errors: errors.length } });
        return { created, updated, errors };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/assets/from-devices",
      tags: ["Assets"],
      summary: "Add an asset for every enrolled device that doesn't have one (matched by serial)",
      security: bearer,
      responses: { 200: json(z.object({ created: z.number().int() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const devices = await sql<{ id: string; hostname: string; serial: string; model: string; platform: string; primary_user_id: string | null }>`
          SELECT d.id, d.hostname, d.serial, d.model, d.platform, d.primary_user_id FROM devices d
          WHERE d.status = 'active' AND d.serial <> ''
            AND NOT EXISTS (SELECT 1 FROM assets a WHERE upper(replace(a.serial, ' ', '')) = upper(replace(d.serial, ' ', '')))
          ORDER BY d.hostname`.execute(tx);
        const tags = new Set((await tx.selectFrom("assets").select("tag").execute()).map((a) => a.tag.toLowerCase()));
        let created = 0;
        for (const d of devices.rows) {
          let tag = d.serial;
          if (tags.has(tag.toLowerCase())) tag = `${d.serial}-${created + 1}`;
          tags.add(tag.toLowerCase());
          const id = newId();
          const make = d.platform === "macos" ? "Apple" : "";
          await tx
            .insertInto("assets")
            .values({ id, org_id: p.orgId, tag, name: d.hostname, kind: KIND_FROM_PLATFORM(d.model), make, model: d.model, serial: d.serial, ...(d.primary_user_id ? { status: "assigned" as const, assigned_to: d.primary_user_id } : {}) })
            .execute();
          await tx.insertInto("asset_events").values({ id: newId(), org_id: p.orgId, asset_id: id, kind: d.primary_user_id ? "checked_out" : "created", user_id: d.primary_user_id, status: d.primary_user_id ? "assigned" : "in_stock", note: "From the enrolled device", actor_id: p.userId }).execute();
          created++;
        }
        if (created) await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "asset.imported", details: { created, source: "devices" } });
        return { created };
      });
      return c.json(out, 200);
    },
  );
}

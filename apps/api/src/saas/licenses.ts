import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { badRequest, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { SAAS_BY_KEY } from "./catalog.js";
import { ssoApps } from "./usage.js";

/**
 * SaaS licenses (docs/SAAS.md): seats, price and renewal per app, and whether the people holding
 * seats use them. A seat is in use when its holder opened the app in a managed browser (SaaS
 * discovery) or signed in to it through Nexus SSO within the window. Seats held by people who've
 * left, or not used at all, are the ones to reclaim.
 */

const RENEWAL_SOON_DAYS = 60;

const HolderStatus = z.enum(["active", "inactive", "departed", "unknown"]);
const LicenseIn = z.object({
  app_key: z.string().regex(/^[a-z0-9-]{1,40}$/),
  plan: z.string().trim().max(100).default(""),
  seats: z.number().int().min(0).max(1_000_000),
  unit_cost: z.number().min(0).max(1_000_000).default(0).openapi({ description: "Price per seat per billing period, e.g. 12.5" }),
  currency: z.string().regex(/^[A-Z]{3}$/).default("USD"),
  billing: z.enum(["monthly", "annual"]).default("annual"),
  renews_on: z.iso.date().nullable().default(null),
  seat_source: z.enum(["sso", "list"]).default("sso").openapi({ description: "sso: people assigned to the app in Nexus hold the seats. list: the seat holders you give" }),
  owner_id: z.string().uuid().nullable().default(null),
  notes: z.string().trim().max(1000).default(""),
});

const LicenseOut = z
  .object({
    id: Id,
    app_key: z.string(),
    app_name: z.string(),
    category: z.string(),
    plan: z.string(),
    seats: z.number().int(),
    unit_cost: z.number(),
    currency: z.string(),
    billing: z.enum(["monthly", "annual"]),
    annual_cost: z.number(),
    renews_on: z.string().nullable(),
    renews_soon: z.boolean(),
    seat_source: z.enum(["sso", "list"]),
    owner: z.object({ id: z.string(), email: z.string() }).nullable(),
    notes: z.string(),
    holders: z.number().int(),
    active: z.number().int(),
    inactive: z.number().int(),
    departed: z.number().int(),
    unassigned: z.number().int().openapi({ description: "Seats paid for that nobody holds" }),
    reclaimable: z.number().int().openapi({ description: "Unassigned seats, plus seats held by people who left or haven't used the app" }),
    reclaimable_annual: z.number(),
    activity_from: z.array(z.enum(["browser", "sso"])).openapi({ description: "Where use is seen. Empty: use can't be judged, so no seat counts as inactive" }),
    sso_app: z.object({ id: z.string(), name: z.string() }).nullable(),
  })
  .openapi("SaasLicense");

type Row = { id: string; app_key: string; plan: string; seats: number; unit_cost_cents: number; currency: string; billing: "monthly" | "annual"; renews_on: string | null; seat_source: "sso" | "list"; owner_id: string | null; owner_email: string | null; notes: string };
type Holder = { email: string; user_id: string | null; name: string; status: z.infer<typeof HolderStatus>; last_used: string | null; via: "browser" | "sso" | null };

const annual = (r: { unit_cost_cents: number; billing: string }) => (Number(r.unit_cost_cents) * (r.billing === "monthly" ? 12 : 1)) / 100;

async function loadRows(tx: Tx, id?: string) {
  let q = tx
    .selectFrom("saas_licenses as l")
    .leftJoin("users as o", "o.id", "l.owner_id")
    .select(["l.id", "l.app_key", "l.plan", "l.seats", "l.unit_cost_cents", "l.currency", "l.billing", sql<string | null>`l.renews_on::text`.as("renews_on"), "l.seat_source", "l.owner_id", "o.email as owner_email", "l.notes"])
    .orderBy("l.created_at");
  if (id) q = q.where("l.id", "=", id);
  return (await q.execute()) as Row[];
}

/** Who holds a license's seats, and whether each used the app within `days`. */
async function holders(tx: Tx, r: Row, days: number, ctx: { sso: Map<string, { id: string; name: string }>; discovery: boolean }): Promise<{ list: Holder[]; from: ("browser" | "sso")[] }> {
  const ssoApp = ctx.sso.get(r.app_key);
  type Person = { email: string; user_id: string | null; name: string; status: string | null };
  let people: Person[];
  if (r.seat_source === "sso") {
    if (!ssoApp) return { list: [], from: [] };
    people = (await sql<Person>`
      SELECT DISTINCT u.email, u.id AS user_id, trim(u.given_name || ' ' || u.family_name) AS name, u.status
      FROM app_assignments a
      LEFT JOIN group_members gm ON a.principal_type = 'group' AND gm.group_id = a.principal_id
      JOIN users u ON u.id = CASE WHEN a.principal_type = 'user' THEN a.principal_id ELSE gm.user_id END
      WHERE a.app_id = ${ssoApp.id}
      ORDER BY u.email`.execute(tx)).rows;
  } else {
    people = (await sql<Person>`
      SELECT h.email, u.id AS user_id, coalesce(trim(u.given_name || ' ' || u.family_name), '') AS name, u.status
      FROM saas_license_holders h LEFT JOIN users u ON lower(u.email) = h.email
      WHERE h.license_id = ${r.id}
      ORDER BY h.email`.execute(tx)).rows;
  }
  const from: ("browser" | "sso")[] = [...(ctx.discovery ? (["browser"] as const) : []), ...(ssoApp ? (["sso"] as const) : [])];
  const browser = new Map(
    (await sql<{ email: string; last: Date }>`SELECT user_email AS email, max(last_at) AS last FROM saas_usage WHERE app_key = ${r.app_key} AND day >= current_date - ${days}::int AND (visits > 0 OR password_logins > 0) GROUP BY user_email`.execute(tx)).rows.map((x) => [x.email.toLowerCase(), new Date(x.last)]),
  );
  const sso = ssoApp
    ? new Map(
        (await sql<{ id: string; last: Date }>`SELECT actor_id AS id, max(ts) AS last FROM audit_events WHERE target_id = ${ssoApp.id} AND type = 'sso.login' AND outcome = 'success' AND ts > now() - make_interval(days => ${days}) GROUP BY actor_id`.execute(tx)).rows.map((x) => [x.id, new Date(x.last)]),
      )
    : new Map<string, Date>();
  const list = people.map((p): Holder => {
    const b = browser.get(p.email.toLowerCase());
    const s = p.user_id ? sso.get(p.user_id) : undefined;
    const last = b && s ? (b > s ? b : s) : (b ?? s);
    const via = last ? (last === b ? "browser" : "sso") : null;
    const left = p.status === "suspended" || p.status === "deprovisioned";
    const status = left ? "departed" : last ? "active" : from.length ? "inactive" : "unknown";
    return { email: p.email, user_id: p.user_id, name: p.name ?? "", status, last_used: last ? iso(last) : null, via };
  });
  return { list, from };
}

async function shape(tx: Tx, r: Row, days: number, ctx: { sso: Map<string, { id: string; name: string }>; discovery: boolean }) {
  const { list, from } = await holders(tx, r, days, ctx);
  const count = (s: Holder["status"]) => list.filter((h) => h.status === s).length;
  const unassigned = Math.max(0, r.seats - list.length);
  const reclaimable = Math.min(r.seats, unassigned + count("inactive") + count("departed"));
  const perSeat = annual(r);
  const app = SAAS_BY_KEY.get(r.app_key);
  const daysLeft = r.renews_on ? (new Date(`${r.renews_on}T00:00:00Z`).getTime() - Date.now()) / 86_400_000 : null;
  return {
    license: {
      id: r.id,
      app_key: r.app_key,
      app_name: app?.name ?? r.app_key,
      category: app?.category ?? "",
      plan: r.plan,
      seats: r.seats,
      unit_cost: Number(r.unit_cost_cents) / 100,
      currency: r.currency,
      billing: r.billing,
      annual_cost: Math.round(perSeat * r.seats * 100) / 100,
      renews_on: r.renews_on,
      renews_soon: daysLeft !== null && daysLeft >= -1 && daysLeft <= RENEWAL_SOON_DAYS,
      seat_source: r.seat_source,
      owner: r.owner_id && r.owner_email ? { id: r.owner_id, email: r.owner_email } : null,
      notes: r.notes,
      holders: list.length,
      active: count("active"),
      inactive: count("inactive"),
      departed: count("departed"),
      unassigned,
      reclaimable,
      reclaimable_annual: Math.round(perSeat * reclaimable * 100) / 100,
      activity_from: from,
      sso_app: ctx.sso.get(r.app_key) ?? null,
    },
    holders: list,
  };
}

async function context(tx: Tx) {
  return { sso: await ssoApps(tx), discovery: (await tx.selectFrom("browser_policies").select("saas_discovery").executeTakeFirst())?.saas_discovery ?? false };
}

export function registerSaasLicenseRoutes(app: App) {
  const Days = z.object({ days: z.coerce.number().int().min(7).max(180).default(30).openapi({ description: "A seat counts as used if its holder used the app within this many days" }) });

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/saas/licenses",
      tags: ["SaaS"],
      summary: "SaaS licenses: what you pay for, and which seats are used",
      security: bearer,
      request: { query: Days },
      responses: {
        200: json(
          z.object({
            data: z.array(LicenseOut),
            totals: z.array(z.object({ currency: z.string(), annual_cost: z.number(), reclaimable_annual: z.number(), seats: z.number().int(), reclaimable: z.number().int() })),
            renewing_soon: z.number().int(),
          }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const { days } = c.req.valid("query");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const ctx = await context(tx);
        const data = [];
        for (const r of await loadRows(tx)) data.push((await shape(tx, r, days, ctx)).license);
        const totals = new Map<string, { currency: string; annual_cost: number; reclaimable_annual: number; seats: number; reclaimable: number }>();
        for (const l of data) {
          const t = totals.get(l.currency) ?? { currency: l.currency, annual_cost: 0, reclaimable_annual: 0, seats: 0, reclaimable: 0 };
          t.annual_cost += l.annual_cost;
          t.reclaimable_annual += l.reclaimable_annual;
          t.seats += l.seats;
          t.reclaimable += l.reclaimable;
          totals.set(l.currency, t);
        }
        return { data, totals: [...totals.values()].map((t) => ({ ...t, annual_cost: Math.round(t.annual_cost * 100) / 100, reclaimable_annual: Math.round(t.reclaimable_annual * 100) / 100 })), renewing_soon: data.filter((l) => l.renews_soon).length };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/saas/licenses/{id}",
      tags: ["SaaS"],
      summary: "A license and its seat holders",
      security: bearer,
      request: { params: z.object({ id: Id }), query: Days },
      responses: {
        200: json(z.object({ license: LicenseOut, holders: z.array(z.object({ email: z.string(), user_id: z.string().nullable(), name: z.string(), status: HolderStatus, last_used: z.string().nullable(), via: z.enum(["browser", "sso"]).nullable() })) })),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const { id } = c.req.valid("param");
      const { days } = c.req.valid("query");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const [r] = await loadRows(tx, id);
        if (!r) throw notFound("License");
        return shape(tx, r, days, await context(tx));
      });
      return c.json(out, 200);
    },
  );

  const write = async (tx: Tx, input: z.infer<typeof LicenseIn>) => {
    if (!SAAS_BY_KEY.has(input.app_key)) throw badRequest("unknown_app", "Pick an app from the catalog");
    if (input.owner_id && !(await tx.selectFrom("users").select("id").where("id", "=", input.owner_id).executeTakeFirst())) throw badRequest("unknown_owner", "No such person");
    return {
      app_key: input.app_key,
      plan: input.plan,
      seats: input.seats,
      unit_cost_cents: Math.round(input.unit_cost * 100),
      currency: input.currency,
      billing: input.billing,
      renews_on: input.renews_on,
      seat_source: input.seat_source,
      owner_id: input.owner_id,
      notes: input.notes,
    };
  };

  app.openapi(
    createRoute({ method: "post", path: "/v1/saas/licenses", tags: ["SaaS"], summary: "Add a license", security: bearer, request: body(LicenseIn), responses: { 201: json(LicenseOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const id = newId();
        await tx.insertInto("saas_licenses").values({ id, org_id: p.orgId, ...(await write(tx, input)) }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "saas.license_created", target: { type: "saas_license", id, display: SAAS_BY_KEY.get(input.app_key)!.name }, details: { app: input.app_key, seats: input.seats, unit_cost: input.unit_cost, currency: input.currency, billing: input.billing } });
        const [r] = await loadRows(tx, id);
        return (await shape(tx, r!, 30, await context(tx))).license;
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "put", path: "/v1/saas/licenses/{id}", tags: ["SaaS"], summary: "Change a license", security: bearer, request: { params: z.object({ id: Id }), ...body(LicenseIn) }, responses: { 200: json(LicenseOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const [before] = await loadRows(tx, id);
        if (!before) throw notFound("License");
        await tx.updateTable("saas_licenses").set({ ...(await write(tx, input)), updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "saas.license_updated",
          target: { type: "saas_license", id, display: SAAS_BY_KEY.get(input.app_key)!.name },
          details: { from: { seats: before.seats, unit_cost: Number(before.unit_cost_cents) / 100, billing: before.billing, renews_on: before.renews_on }, to: { seats: input.seats, unit_cost: input.unit_cost, billing: input.billing, renews_on: input.renews_on } },
        });
        const [r] = await loadRows(tx, id);
        return (await shape(tx, r!, 30, await context(tx))).license;
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/saas/licenses/{id}", tags: ["SaaS"], summary: "Remove a license", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const [r] = await loadRows(tx, id);
        if (!r) throw notFound("License");
        await tx.deleteFrom("saas_licenses").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "saas.license_deleted", target: { type: "saas_license", id, display: SAAS_BY_KEY.get(r.app_key)?.name ?? r.app_key } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/saas/licenses/{id}/holders",
      tags: ["SaaS"],
      summary: "Set who holds the seats (for licenses whose seats come from a list)",
      description: "Replaces the list. Emails are matched to people in Nexus; others are kept as they are (contractors, shared accounts).",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ emails: z.array(z.string().trim().toLowerCase().pipe(z.email())).max(20_000) })) },
      responses: { 200: json(z.object({ holders: z.number().int(), added: z.number().int(), removed: z.number().int() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      const emails = [...new Set(c.req.valid("json").emails)];
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const [r] = await loadRows(tx, id);
        if (!r) throw notFound("License");
        if (r.seat_source !== "list") throw badRequest("seats_from_sso", "This license's seats are the people assigned to the app in Nexus: change them under Applications");
        const before = new Set((await tx.selectFrom("saas_license_holders").select("email").where("license_id", "=", id).execute()).map((x) => x.email));
        const next = new Set(emails);
        const removed = [...before].filter((e) => !next.has(e));
        const added = emails.filter((e) => !before.has(e));
        if (removed.length) await tx.deleteFrom("saas_license_holders").where("license_id", "=", id).where("email", "in", removed).execute();
        for (let i = 0; i < added.length; i += 1000) {
          await tx.insertInto("saas_license_holders").values(added.slice(i, i + 1000).map((email) => ({ license_id: id, org_id: p.orgId, email }))).execute();
        }
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "saas.license_holders_updated", target: { type: "saas_license", id, display: SAAS_BY_KEY.get(r.app_key)?.name ?? r.app_key }, details: { added: added.length, removed: removed.length, holders: emails.length } });
        return { holders: emails.length, added: added.length, removed: removed.length };
      });
      return c.json(out, 200);
    },
  );
}

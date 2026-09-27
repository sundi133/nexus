import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { badRequest, notFound } from "../platform/errors.js";
import { bearer, body, iso, json, problemResponses } from "../schemas.js";
import { SAAS_APPS, SAAS_BY_KEY, SAAS_CATEGORIES, slug } from "./catalog.js";

/**
 * SaaS management (docs/SAAS.md): which apps people use (from the browser extension, while
 * discovery is on), which are approved, and what browsers do about the rest.
 */

const Status = z.enum(["unreviewed", "approved", "unapproved"]);
const Action = z.enum(["allow", "warn", "block"]);
const Key = z.string().regex(/^[a-z0-9-]{1,40}$/);

const AppOut = z
  .object({
    key: z.string(),
    name: z.string(),
    category: z.string(),
    hosts: z.array(z.string()),
    status: Status,
    action: Action.openapi({ description: "For unapproved apps: what browsers do (allow and count, warn, or block)" }),
    owner: z.object({ id: z.string(), email: z.string() }).nullable(),
    notes: z.string(),
    people: z.number().int(),
    visits: z.number().int(),
    password_logins: z.number().int().openapi({ description: "Sign-ins with a password rather than SSO" }),
    password_people: z.number().int(),
    blocked: z.number().int(),
    last_seen: z.string().nullable(),
    sso: z.object({ id: z.string(), name: z.string() }).nullable().openapi({ description: "The Nexus application for it, if it's set up for single sign-on" }),
  })
  .openapi("SaasApp");

type Usage = { app_key: string; people: number; visits: number; password_logins: number; password_people: number; blocked: number; last_seen: Date | null };

async function usage(tx: Tx, days: number, appKey?: string) {
  let q = tx
    .selectFrom("saas_usage")
    .select([
      "app_key",
      sql<number>`count(DISTINCT user_email) FILTER (WHERE visits > 0 OR password_logins > 0)`.as("people"),
      sql<number>`coalesce(sum(visits), 0)`.as("visits"),
      sql<number>`coalesce(sum(password_logins), 0)`.as("password_logins"),
      sql<number>`count(DISTINCT user_email) FILTER (WHERE password_logins > 0)`.as("password_people"),
      sql<number>`coalesce(sum(blocked), 0)`.as("blocked"),
      sql<Date | null>`max(last_at)`.as("last_seen"),
    ])
    .where("day", ">=", sql<string>`current_date - ${days}::int`)
    .groupBy("app_key");
  if (appKey) q = q.where("app_key", "=", appKey);
  return new Map((await q.execute()).map((r) => [r.app_key, r as Usage]));
}

/** Nexus SSO applications, matched to catalog apps by their template or their name. */
async function ssoApps(tx: Tx) {
  const rows = await tx.selectFrom("applications").select(["id", "name", "catalog_key"]).execute();
  const out = new Map<string, { id: string; name: string }>();
  for (const r of rows) {
    for (const k of [r.catalog_key ? slug(r.catalog_key) : "", slug(r.name)]) if (k && SAAS_BY_KEY.has(k) && !out.has(k)) out.set(k, { id: r.id, name: r.name });
  }
  return out;
}

async function decisions(tx: Tx) {
  const rows = await tx.selectFrom("saas_apps").leftJoin("users", "users.id", "saas_apps.owner_id").select(["saas_apps.app_key", "saas_apps.status", "saas_apps.action", "saas_apps.owner_id", "users.email", "saas_apps.notes"]).execute();
  return new Map(rows.map((r) => [r.app_key, r]));
}

function shape(key: string, u: Usage | undefined, d: Awaited<ReturnType<typeof decisions>> extends Map<string, infer V> ? V | undefined : never, sso: { id: string; name: string } | undefined): z.infer<typeof AppOut> {
  const a = SAAS_BY_KEY.get(key)!;
  return {
    key,
    name: a.name,
    category: a.category,
    hosts: a.hosts,
    status: d?.status ?? "unreviewed",
    action: d?.status === "unapproved" ? d.action : "allow",
    owner: d?.owner_id && d.email ? { id: d.owner_id, email: d.email } : null,
    notes: d?.notes ?? "",
    people: Number(u?.people ?? 0),
    visits: Number(u?.visits ?? 0),
    password_logins: Number(u?.password_logins ?? 0),
    password_people: Number(u?.password_people ?? 0),
    blocked: Number(u?.blocked ?? 0),
    last_seen: u?.last_seen ? iso(new Date(u.last_seen)) : null,
    sso: sso ?? null,
  };
}

export function registerSaasRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/saas/apps",
      tags: ["SaaS"],
      summary: "SaaS apps people use, and what the organization decided about them",
      description: "Apps seen in managed browsers in the last `days` (while discovery is on), plus every app with a decision.",
      security: bearer,
      request: { query: z.object({ days: z.coerce.number().int().min(1).max(180).default(30), status: Status.optional(), q: z.string().max(100).optional() }) },
      responses: {
        200: json(
          z.object({
            data: z.array(AppOut),
            summary: z.object({ discovery: z.boolean(), apps: z.number().int(), people: z.number().int(), unreviewed: z.number().int(), unapproved_in_use: z.number().int(), password_apps: z.number().int().openapi({ description: "Apps set up for SSO that people still sign in to with a password" }) }),
          }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const q = c.req.valid("query");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const [u, d, sso, pol] = [await usage(tx, q.days), await decisions(tx), await ssoApps(tx), await tx.selectFrom("browser_policies").select("saas_discovery").executeTakeFirst()];
        const people = await tx
          .selectFrom("saas_usage")
          .select(sql<number>`count(DISTINCT user_email)`.as("n"))
          .where("day", ">=", sql<string>`current_date - ${q.days}::int`)
          .where((eb) => eb.or([eb("visits", ">", 0), eb("password_logins", ">", 0)]))
          .executeTakeFirstOrThrow();
        const keys = [...new Set([...u.keys(), ...d.keys()])].filter((k) => SAAS_BY_KEY.has(k));
        const all = keys.map((k) => shape(k, u.get(k), d.get(k), sso.get(k))).filter((a) => a.people || a.blocked || a.status !== "unreviewed");
        const needle = q.q?.toLowerCase();
        const data = all
          .filter((a) => (!q.status || a.status === q.status) && (!needle || a.name.toLowerCase().includes(needle) || a.category.toLowerCase().includes(needle)))
          .sort((x, y) => y.people - x.people || y.visits - x.visits || x.name.localeCompare(y.name));
        return {
          data,
          summary: {
            discovery: pol?.saas_discovery ?? false,
            apps: all.filter((a) => a.people).length,
            people: Number(people.n),
            unreviewed: all.filter((a) => a.status === "unreviewed" && a.people).length,
            unapproved_in_use: all.filter((a) => a.status === "unapproved" && a.people).length,
            password_apps: all.filter((a) => a.sso && a.password_logins).length,
          },
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/saas/apps/{key}",
      tags: ["SaaS"],
      summary: "One SaaS app: who uses it and how they sign in",
      security: bearer,
      request: { params: z.object({ key: Key }), query: z.object({ days: z.coerce.number().int().min(1).max(180).default(30) }) },
      responses: {
        200: json(
          z.object({
            app: AppOut,
            people: z.array(z.object({ email: z.string(), user_id: z.string().nullable(), name: z.string(), visits: z.number().int(), password_logins: z.number().int(), blocked: z.number().int(), last_seen: z.string() })),
          }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const { key } = c.req.valid("param");
      const { days } = c.req.valid("query");
      if (!SAAS_BY_KEY.has(key)) throw notFound("App");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const rows = await tx
          .selectFrom("saas_usage as s")
          .leftJoin("users", "users.id", "s.user_id")
          .select([
            "s.user_email",
            sql<string | null>`max(s.user_id::text)`.as("user_id"),
            sql<string>`coalesce(max(users.given_name || ' ' || users.family_name), '')`.as("name"),
            sql<number>`sum(s.visits)`.as("visits"),
            sql<number>`sum(s.password_logins)`.as("password_logins"),
            sql<number>`sum(s.blocked)`.as("blocked"),
            sql<Date>`max(s.last_at)`.as("last_seen"),
          ])
          .where("s.app_key", "=", key)
          .where("s.day", ">=", sql<string>`current_date - ${days}::int`)
          .groupBy("s.user_email")
          .orderBy(sql`max(s.last_at)`, "desc")
          .execute();
        return {
          app: shape(key, (await usage(tx, days, key)).get(key), (await decisions(tx)).get(key), (await ssoApps(tx)).get(key)),
          people: rows.map((r) => ({ email: r.user_email || "(browser not signed in)", user_id: r.user_id, name: r.name.trim(), visits: Number(r.visits), password_logins: Number(r.password_logins), blocked: Number(r.blocked), last_seen: iso(new Date(r.last_seen)) })),
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/saas/apps/{key}",
      tags: ["SaaS"],
      summary: "Approve an app, or mark it unapproved and choose what browsers do",
      description: "Warning or blocking needs a recent MFA. Browsers pick up the change on their next sync (about a minute).",
      security: bearer,
      request: { params: z.object({ key: Key }), ...body(z.object({ status: Status, action: Action.default("allow"), owner_id: z.string().uuid().nullable().default(null), notes: z.string().trim().max(1000).default("") })) },
      responses: { 200: json(AppOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { key } = c.req.valid("param");
      const input = c.req.valid("json");
      if (!SAAS_BY_KEY.has(key)) throw notFound("App");
      if (input.status !== "unapproved" && input.action !== "allow") throw badRequest("action_needs_unapproved", "Only unapproved apps can be warned about or blocked");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        if (input.action !== "allow") requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        if (input.owner_id && !(await tx.selectFrom("users").select("id").where("id", "=", input.owner_id).executeTakeFirst())) throw badRequest("unknown_owner", "No such person");
        const before = (await decisions(tx)).get(key);
        if (input.status === "unreviewed") await tx.deleteFrom("saas_apps").where("app_key", "=", key).execute();
        else {
          const row = { status: input.status, action: input.action, owner_id: input.owner_id, notes: input.notes, updated_at: new Date(), updated_by: p.userId };
          await tx.insertInto("saas_apps").values({ org_id: p.orgId, app_key: key, ...row }).onConflict((oc) => oc.columns(["org_id", "app_key"]).doUpdateSet(row)).execute();
        }
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "saas.app_reviewed",
          target: { type: "saas_app", id: null, display: SAAS_BY_KEY.get(key)!.name },
          details: { app: key, from: { status: before?.status ?? "unreviewed", action: before?.action ?? "allow" }, to: { status: input.status, action: input.action } },
        });
        return shape(key, (await usage(tx, 30, key)).get(key), (await decisions(tx)).get(key), (await ssoApps(tx)).get(key));
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/saas/catalog",
      tags: ["SaaS"],
      summary: "Search the SaaS apps Nexus recognises",
      security: bearer,
      request: { query: z.object({ q: z.string().max(100).default(""), category: z.string().max(60).optional(), limit: z.coerce.number().int().min(1).max(200).default(50) }) },
      responses: { 200: json(z.object({ data: z.array(z.object({ key: z.string(), name: z.string(), category: z.string(), hosts: z.array(z.string()) })), total: z.number().int(), categories: z.array(z.string()) })), ...problemResponses },
    }),
    (c) => {
      requirePermission(c, "apps:read");
      const q = c.req.valid("query");
      const needle = q.q.toLowerCase();
      const hits = SAAS_APPS.filter((a) => (!q.category || a.category === q.category) && (!needle || a.name.toLowerCase().includes(needle) || a.hosts.some((h) => h.includes(needle))));
      return c.json({ data: hits.slice(0, q.limit), total: SAAS_APPS.length, categories: SAAS_CATEGORIES }, 200);
    },
  );
}

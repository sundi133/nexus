import { createHash, randomBytes } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { AI_APPS, APP_KEYS } from "./catalog.js";

/**
 * AI apps in the browser (the Nexus browser extension). Managed browsers are configured with an
 * organization token; they fetch the policy (what to allow, warn about or block, and which
 * sensitive data to stop) and report what happened. Pasted text is scanned in the browser and
 * never sent: events carry the detector and a masked hint only.
 */

const AppAction = z.enum(["allow", "warn", "block"]);
const DlpAction = z.enum(["off", "monitor", "warn", "block"]);
const DETECTOR_IDS = ["secret", "private_key", "credit_card", "us_ssn", "iban", "email_list"] as const;
const DEFAULT_DLP: Record<(typeof DETECTOR_IDS)[number], z.infer<typeof DlpAction>> = {
  secret: "block",
  private_key: "block",
  credit_card: "warn",
  us_ssn: "warn",
  iban: "monitor",
  email_list: "monitor",
};

/** Patterns run in people's browsers on everything they paste: keep them simple and bounded. */
const CustomPattern = z.object({
  id: z.string().regex(/^[a-z0-9_-]{1,40}$/),
  name: z.string().trim().min(1).max(80),
  pattern: z
    .string()
    .min(2)
    .max(200)
    .refine((p) => {
      try {
        new RegExp(p, "gi");
        return true;
      } catch {
        return false;
      }
    }, "Not a valid regular expression")
    .refine((p) => !/\([^)]*[+*][^)]*\)[+*{]/.test(p), "Nested repetition (like (a+)+) can freeze a browser; simplify the pattern"),
  action: DlpAction,
});

const PolicyIn = z
  .object({
    apps: z.record(z.string(), AppAction).default({}).openapi({ description: "App key → allow, warn or block; apps not listed are allowed" }),
    dlp: z
      .object({
        detectors: z.partialRecord(z.enum(DETECTOR_IDS), DlpAction).default({}),
        custom: z.array(CustomPattern).max(50).default([]),
      })
      .default({ detectors: {}, custom: [] }),
    uploads: z.enum(["allow", "warn", "block"]).default("allow").openapi({ description: "File uploads to AI apps" }),
    message: z.string().trim().max(500).default("").openapi({ description: "Shown to people on warnings and blocks, e.g. a link to your AI policy" }),
  })
  .openapi("BrowserPolicyInput");

type Policy = { apps: Record<string, "allow" | "warn" | "block">; dlp: { detectors: Record<string, string>; custom: z.infer<typeof CustomPattern>[] }; uploads: "allow" | "warn" | "block"; message: string; updated_at: Date | null };

async function loadPolicy(tx: Tx): Promise<Policy> {
  const r = await tx.selectFrom("browser_policies").selectAll().executeTakeFirst();
  const dlp = (r?.dlp ?? {}) as { detectors?: Record<string, string>; custom?: z.infer<typeof CustomPattern>[] };
  return {
    apps: Object.fromEntries(Object.entries((r?.apps ?? {}) as Record<string, "allow" | "warn" | "block">).filter(([k]) => APP_KEYS.has(k))),
    dlp: { detectors: { ...DEFAULT_DLP, ...(dlp.detectors ?? {}) }, custom: dlp.custom ?? [] },
    uploads: r?.uploads ?? "allow",
    message: r?.message ?? "",
    updated_at: r?.updated_at ?? null,
  };
}

/** What the extension gets: the catalog with actions, and the version it compares against. */
function extensionPolicy(p: Policy) {
  const body = {
    apps: AI_APPS.map((a) => ({ key: a.key, name: a.name, hosts: a.hosts, action: p.apps[a.key] ?? "allow" })),
    dlp: { detectors: p.dlp.detectors, custom: p.dlp.custom },
    uploads: p.uploads,
    message: p.message,
  };
  return { version: createHash("sha256").update(JSON.stringify(body)).digest("hex").slice(0, 16), ...body };
}

const PolicyOut = z
  .object({
    apps: z.array(z.object({ key: z.string(), name: z.string(), vendor: z.string(), category: z.string(), hosts: z.array(z.string()), action: AppAction })),
    dlp: z.object({ detectors: z.record(z.string(), DlpAction), custom: z.array(CustomPattern) }),
    uploads: z.enum(["allow", "warn", "block"]),
    message: z.string(),
    version: z.string(),
    updated_at: z.string().nullable(),
    server: z.string().openapi({ description: "The API address browsers are configured with" }),
  })
  .openapi("BrowserPolicy");

const policyOut = (p: Policy, server: string) => ({
  server,
  apps: AI_APPS.map((a) => ({ key: a.key, name: a.name, vendor: a.vendor, category: a.category, hosts: a.hosts, action: p.apps[a.key] ?? ("allow" as const) })),
  dlp: p.dlp as z.infer<typeof PolicyOut>["dlp"],
  uploads: p.uploads,
  message: p.message,
  version: extensionPolicy(p).version,
  updated_at: isoOrNull(p.updated_at),
});

const EventIn = z.object({
  at: z.iso.datetime(),
  kind: z.enum(["visit", "dlp", "upload"]),
  action: z.enum(["allowed", "monitored", "warned", "continued", "blocked"]),
  app: z.string().max(40).default(""),
  host: z.string().max(253).default(""),
  detector: z.string().max(60).default(""),
  count: z.number().int().min(1).max(100_000).default(1),
  detail: z.string().max(300).default(""),
});

const SyncIn = z.object({
  user: z.string().max(320).default("").openapi({ description: "The browser profile's email (managed Chrome/Edge)" }),
  extension_version: z.string().max(40).default(""),
  policy_version: z.string().max(40).default(""),
  // Checked one by one below: a malformed event is skipped, not a reason to refuse the batch
  // (which the browser would then resend forever).
  events: z.array(z.unknown()).max(500).default([]).openapi({ description: "Up to 500 events: at, kind (visit|dlp|upload), action, app, host, detector, count, detail" }),
});

const hashToken = (t: string) => createHash("sha256").update(t).digest();

export function registerBrowserRoutes(app: App) {
  // ---- The extension ---------------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/browser/extension/sync",
      tags: ["Browser"],
      summary: "The browser extension reports events and gets the current policy",
      description: "Authenticated with the organization's extension token: `Authorization: NexusBrowser nxb_…`. Returns the policy when `policy_version` differs from the current one.",
      request: body(SyncIn),
      responses: { 200: json(z.object({ version: z.string(), policy: z.unknown().nullable(), accepted: z.number().int() })), ...problemResponses },
    }),
    async (c) => {
      const auth = c.req.header("authorization") ?? "";
      const token = auth.startsWith("NexusBrowser ") ? auth.slice(13).trim() : "";
      const deps = c.get("deps");
      const found = token ? await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; token_id: string }>`SELECT * FROM nexus_browser_token_lookup(${hashToken(token)})`.execute(tx)).rows[0]) : undefined;
      if (!found) throw new ApiError(401, "unauthenticated", "Unknown or revoked extension token");
      const input = c.req.valid("json");
      const out = await deps.db.tenant(found.org_id, async (tx) => {
        const email = input.user.trim().toLowerCase();
        const user = email ? await tx.selectFrom("users").select("id").where(sql`lower(email)`, "=", email).executeTakeFirst() : undefined;
        const events = input.events.flatMap((raw) => {
          const e = EventIn.safeParse(raw);
          return e.success ? [e.data] : [];
        });
        for (const e of events) {
          await tx
            .insertInto("browser_events")
            .values({ id: newId(), org_id: found.org_id, at: new Date(e.at), user_email: email, user_id: user?.id ?? null, kind: e.kind, action: e.action, app: APP_KEYS.has(e.app) ? e.app : "", host: e.host.toLowerCase(), detector: e.detector, count: e.count, detail: e.detail, extension_version: input.extension_version })
            .execute();
          // Sensitive data and uploads stopped or let through after a warning are security events.
          if (e.kind !== "visit" && (e.action === "blocked" || e.action === "continued")) {
            await audit(tx, found.org_id, { meta: c.get("meta") }, {
              type: e.action === "blocked" ? `browser.${e.kind}_blocked` : `browser.${e.kind}_continued`,
              outcome: e.action === "blocked" ? "failure" : "success",
              actor: { type: user ? "user" : "system", id: user?.id ?? null, display: email || "unknown browser user" },
              target: { type: "ai_app", id: null, display: AI_APPS.find((a) => a.key === e.app)?.name ?? e.host },
              details: { detector: e.detector, count: e.count, detail: e.detail, host: e.host },
            });
          }
        }
        const p = extensionPolicy(await loadPolicy(tx));
        return { version: p.version, policy: input.policy_version === p.version ? null : p, accepted: events.length };
      });
      return c.json(out, 200);
    },
  );

  // ---- Admins -------------------------------------------------------------------------------------

  app.openapi(
    createRoute({ method: "get", path: "/v1/browser/policy", tags: ["Browser"], summary: "AI apps in the browser: what's allowed, and sensitive-data protection", security: bearer, responses: { 200: json(PolicyOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      return c.json(policyOut(await c.get("deps").db.tenant(p.orgId, loadPolicy), c.get("deps").cfg.apiPublicUrl), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/browser/policy",
      tags: ["Browser"],
      summary: "Set what's allowed in AI apps, and sensitive-data protection",
      description: "Needs `devices:enforce` and a recent MFA. Browsers pick up the change on their next sync (within about a minute).",
      security: bearer,
      request: body(PolicyIn),
      responses: { 200: json(PolicyOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const input = c.req.valid("json");
      const unknown = Object.keys(input.apps).filter((k) => !APP_KEYS.has(k));
      if (unknown.length) throw badRequest("unknown_app", `Unknown apps: ${unknown.join(", ")}`);
      const ids = input.dlp.custom.map((x) => x.id);
      if (new Set(ids).size !== ids.length) throw badRequest("duplicate_pattern", "Custom pattern IDs must be unique");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const before = await loadPolicy(tx);
        const row = { apps: JSON.stringify(input.apps), dlp: JSON.stringify(input.dlp), uploads: input.uploads, message: input.message, updated_at: new Date(), updated_by: p.userId };
        await tx.insertInto("browser_policies").values({ org_id: p.orgId, ...row }).onConflict((oc) => oc.column("org_id").doUpdateSet(row)).execute();
        const after = await loadPolicy(tx);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "browser.policy_updated",
          details: { from: { apps: before.apps, dlp: before.dlp, uploads: before.uploads }, to: { apps: after.apps, dlp: after.dlp, uploads: after.uploads } },
        });
        return policyOut(after, c.get("deps").cfg.apiPublicUrl);
      });
      return c.json(out, 200);
    },
  );

  const TokenOut = z.object({ id: Id, name: z.string(), created_by: z.string().nullable(), created_at: z.string(), last_used_at: z.string().nullable(), revoked_at: z.string().nullable() }).openapi("BrowserToken");

  app.openapi(
    createRoute({ method: "get", path: "/v1/browser/tokens", tags: ["Browser"], summary: "Extension tokens", security: bearer, responses: { 200: json(z.object({ data: z.array(TokenOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx.selectFrom("browser_tokens").leftJoin("users", "users.id", "browser_tokens.created_by").selectAll("browser_tokens").select("users.email").orderBy("browser_tokens.created_at", "desc").execute(),
      );
      return c.json({ data: rows.map((r) => ({ id: r.id, name: r.name, created_by: r.email, created_at: iso(r.created_at), last_used_at: isoOrNull(r.last_used_at), revoked_at: isoOrNull(r.revoked_at) })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/browser/tokens",
      tags: ["Browser"],
      summary: "Create an extension token (shown once)",
      description: "Browsers are configured with it through managed policy (Google Admin, Intune, Group Policy). It identifies the organization, not a person: what browsers report is self-reported telemetry.",
      security: bearer,
      request: body(z.object({ name: z.string().trim().min(1).max(100) })),
      responses: { 201: json(TokenOut.extend({ token: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const { name } = c.req.valid("json");
      const token = `nxb_${randomBytes(24).toString("base64url")}`;
      const id = newId();
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        await tx.insertInto("browser_tokens").values({ id, org_id: p.orgId, name, token_hash: hashToken(token), created_by: p.userId, last_used_at: null, revoked_at: null }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "browser.token_created", target: { type: "browser_token", id, display: name } });
        return { id, name, created_by: p.email, created_at: new Date().toISOString(), last_used_at: null, revoked_at: null, token };
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/browser/tokens/{id}", tags: ["Browser"], summary: "Revoke an extension token", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Revoked" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const t = await tx.updateTable("browser_tokens").set({ revoked_at: new Date() }).where("id", "=", id).where("revoked_at", "is", null).returning("name").executeTakeFirst();
        if (!t) throw notFound("Token");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "browser.token_revoked", target: { type: "browser_token", id, display: t.name } });
      });
      return c.body(null, 204);
    },
  );

  const EventOut = z
    .object({ id: Id, at: z.string(), user_email: z.string(), user_id: z.string().nullable(), kind: z.string(), action: z.string(), app: z.string(), app_name: z.string(), host: z.string(), detector: z.string(), count: z.number().int(), detail: z.string() })
    .openapi("BrowserEvent");

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/browser/events",
      tags: ["Browser"],
      summary: "What browsers reported: AI app use, warnings, blocks and sensitive data",
      security: bearer,
      request: { query: z.object({ kind: z.enum(["visit", "dlp", "upload"]).optional(), action: z.string().max(20).optional(), app: z.string().max(40).optional(), limit: z.coerce.number().int().min(1).max(500).default(100) }) },
      responses: { 200: json(z.object({ data: z.array(EventOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const q = c.req.valid("query");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) => {
        let s = tx.selectFrom("browser_events").selectAll().orderBy("at", "desc").limit(q.limit);
        if (q.kind) s = s.where("kind", "=", q.kind);
        if (q.action) s = s.where("action", "=", q.action as "blocked");
        if (q.app) s = s.where("app", "=", q.app);
        return s.execute();
      });
      const name = (k: string) => AI_APPS.find((a) => a.key === k)?.name ?? "";
      return c.json({ data: rows.map((r) => ({ id: r.id, at: iso(r.at), user_email: r.user_email, user_id: r.user_id, kind: r.kind, action: r.action, app: r.app, app_name: name(r.app), host: r.host, detector: r.detector, count: r.count, detail: r.detail })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/browser/usage",
      tags: ["Browser"],
      summary: "AI apps people use in the browser (30 days)",
      security: bearer,
      responses: {
        200: json(
          z.object({
            data: z.array(z.object({ app: z.string(), name: z.string(), vendor: z.string(), people: z.number().int(), visits: z.number().int(), sensitive: z.number().int(), blocked: z.number().int() })),
            browsers: z.object({ people: z.number().int(), last_seen_at: z.string().nullable() }),
          }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const since = new Date(Date.now() - 30 * 86_400_000);
        const rows = await tx
          .selectFrom("browser_events")
          .select([
            "app",
            (eb) => eb.fn.count<number>("user_email").distinct().as("people"),
            sql<number>`coalesce(sum(count) FILTER (WHERE kind = 'visit'), 0)`.as("visits"),
            sql<number>`coalesce(sum(count) FILTER (WHERE kind <> 'visit'), 0)`.as("sensitive"),
            sql<number>`coalesce(sum(count) FILTER (WHERE action = 'blocked'), 0)`.as("blocked"),
          ])
          .where("at", ">", since)
          .where("app", "<>", "")
          .groupBy("app")
          .execute();
        const totals = await tx.selectFrom("browser_events").select([(eb) => eb.fn.count<number>("user_email").distinct().as("people"), (eb) => eb.fn.max("received_at").as("last")]).where("at", ">", since).executeTakeFirstOrThrow();
        const byApp = new Map(rows.map((r) => [r.app, r]));
        return {
          data: AI_APPS.map((a) => ({ app: a.key, name: a.name, vendor: a.vendor, people: Number(byApp.get(a.key)?.people ?? 0), visits: Number(byApp.get(a.key)?.visits ?? 0), sensitive: Number(byApp.get(a.key)?.sensitive ?? 0), blocked: Number(byApp.get(a.key)?.blocked ?? 0) }))
            .filter((x) => x.visits || x.sensitive || x.blocked)
            .sort((x, y) => y.people - x.people || y.visits - x.visits),
          browsers: { people: Number(totals.people), last_seen_at: totals.last ? iso(totals.last as Date) : null },
        };
      });
      return c.json(out, 200);
    },
  );
}

import { createHash } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import type { App, Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { assertDeviceInScope, requirePermission, requireRecentMfa } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import type { DevicePlatform } from "../platform/db-types.js";
import { badRequest, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { commandKey, sign } from "./commands.js";

/**
 * Device enforcement (DEV-ENF): block apps and domains on devices.
 *
 * - App rules: the agent watches process launches (about every 2 seconds) and
 *   terminates matches by executable name, path (or folder) or SHA-256. That
 *   stops an app within seconds; it doesn't prevent the launch.
 * - Domain rules: the agent sinkholes the domain in a Nexus-managed section of
 *   the hosts file. Normal apps can't reach it; a local admin, DNS-over-HTTPS or
 *   a raw IP can.
 *
 * Rules start in monitor mode (report what would be stopped). Each device gets
 * the rules that apply to it as a policy signed with the organization's command
 * key, which the agent pinned at enrollment; a newer policy replaces an older
 * one, and an older one is refused, so neither a network attacker nor a replayed
 * response can change what a device blocks.
 */

export const POLICY_TYP = "nexus-policy+jwt";
const MAX_RULES = 500;

/** Never blocked: the OS, sign-in, remote access and Nexus itself. The agent refuses them too. */
const PROTECTED = new Set(
  [
    "launchd", "kernel_task", "windowserver", "loginwindow", "securityd", "opendirectoryd", "mds", "coreservicesd", "syspolicyd", "trustd", "cfprefsd", "sshd",
    "systemd", "init", "dbus-daemon", "networkmanager", "systemd-logind", "gdm", "sddm", "xorg",
    "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe", "smss.exe", "svchost.exe", "explorer.exe", "dwm.exe", "system", "registry", "msmpeng.exe",
    "nexus-agent", "nexus-agent.exe", "osqueryd", "osqueryd.exe", "osqueryi", "osqueryi.exe",
  ].map((s) => s.toLowerCase()),
);
const PROTECTED_PATHS = ["/system/", "/usr/libexec/", "/sbin/", "c:\\windows\\system32\\", "/library/application support/nexus/", "c:\\program files\\nexus\\", "/opt/nexus/"];

const Kind = z.enum(["app", "domain"]);
const Match = z.enum(["name", "path", "sha256", "domain"]);
const Mode = z.enum(["monitor", "block"]);
const Target = z.union([z.object({ all: z.literal(true) }), z.object({ group_ids: z.array(Id).min(1).max(50) })]);
const Platforms = z.array(z.enum(["macos", "windows", "linux"])).min(1).max(3);

/** Normalises a rule's value, or says why it can't be a rule. */
export function checkRule(r: { kind: "app" | "domain"; match: string; value: string }, own: string[]): { value: string } | { error: string } {
  const v = r.value.trim();
  if (r.kind === "domain") {
    if (r.match !== "domain") return { error: "A domain rule matches a domain" };
    const d = v.toLowerCase().replace(/\.$/, "");
    if (!/^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d)) return { error: "Give a domain name, like chat.example.com (no wildcards, schemes or paths)" };
    if (own.some((h) => h === d || h.endsWith(`.${d}`))) return { error: "That would cut devices off from Nexus itself" };
    return { value: d };
  }
  if (r.match === "domain") return { error: "An app rule matches a name, a path or a SHA-256" };
  if (r.match === "sha256") {
    const h = v.toLowerCase();
    return /^[0-9a-f]{64}$/.test(h) ? { value: h } : { error: "A SHA-256 is 64 hexadecimal characters" };
  }
  if (r.match === "name") {
    if (!v || v.length > 255 || /[\\/]/.test(v)) return { error: "Give the program's file name, like Cursor or ollama.exe (no folders)" };
    if (PROTECTED.has(v.toLowerCase())) return { error: `${v} is part of the operating system or Nexus and can't be blocked` };
    return { value: v };
  }
  // path: an executable, or a folder when it ends with a separator.
  if (!/^(\/|[a-zA-Z]:\\)/.test(v) || v.length > 1000) return { error: "Give a full path, like /Applications/Example.app/ or C:\\Program Files\\Example\\" };
  const lower = v.toLowerCase();
  if (lower === "/" || /^[a-z]:\\$/.test(lower)) return { error: "That would match every program" };
  if (PROTECTED_PATHS.some((p) => lower.startsWith(p) || p.startsWith(lower))) return { error: "That folder holds the operating system or Nexus and can't be blocked" };
  return { value: v };
}

// ---- The policy each device enforces ------------------------------------------------------

type PolicyRule = { id: string; name: string; kind: "app" | "domain"; match: "name" | "path" | "sha256" | "domain"; value: string; mode: "monitor" | "block" };

async function rulesFor(tx: Tx, device: { id: string; platform: DevicePlatform; primary_user_id: string | null }): Promise<PolicyRule[]> {
  const rules = await tx.selectFrom("enforcement_rules").selectAll().where("enabled", "=", true).orderBy("created_at").execute();
  const groups = device.primary_user_id
    ? new Set((await tx.selectFrom("group_members").select("group_id").where("user_id", "=", device.primary_user_id).execute()).map((g) => g.group_id))
    : new Set<string>();
  return rules
    .filter((r) => r.platforms.includes(device.platform))
    .filter((r) => r.target.all || (r.target.group_ids ?? []).some((g) => groups.has(g)))
    .map((r) => ({ id: r.id, name: r.name, kind: r.kind, match: r.match, value: r.value, mode: r.kind === "domain" ? "block" : r.mode }));
}

export const policyVersion = (rules: PolicyRule[]) => createHash("sha256").update(JSON.stringify(rules)).digest("hex").slice(0, 16);

/** The device's current policy, signed, for the check-in response. */
export async function signedPolicy(tx: Tx, deps: Deps, device: { id: string; org_id: string; platform: DevicePlatform; primary_user_id: string | null }) {
  const rules = await rulesFor(tx, device);
  const key = await commandKey(tx, deps, device.org_id);
  // ts orders policies: the agent refuses one older than what it already applied (a replayed response).
  return sign(key.privatePem, { sub: device.id, ts: Date.now(), ver: policyVersion(rules), rules }, POLICY_TYP);
}

// ---- What agents report -------------------------------------------------------------------------

export const EnforcementReport = z.object({
  version: z.string().max(64).default(""),
  status: z.string().max(500).default(""),
  events: z
    .array(
      z.object({
        rule_id: z.string().max(64),
        action: z.enum(["terminated", "would_terminate", "failed"]),
        subject: z.string().max(1000).default(""),
        user: z.string().max(200).default(""),
        count: z.number().int().min(1).max(1_000_000).default(1),
        detail: z.string().max(500).default(""),
        at: z.string().datetime(),
      }),
    )
    .max(100)
    .default([]),
});

export async function recordEnforcement(tx: Tx, device: { id: string; org_id: string; hostname: string }, rep: z.infer<typeof EnforcementReport>, meta: RequestMeta) {
  await tx.updateTable("devices").set({ enforcement_version: rep.version, enforcement_status: rep.status }).where("id", "=", device.id).execute();
  if (!rep.events.length) return;
  const known = new Map((await tx.selectFrom("enforcement_rules").select(["id", "name"]).execute()).map((r) => [r.id, r.name]));
  for (const e of rep.events) {
    const ruleId = known.has(e.rule_id) ? e.rule_id : null;
    const name = known.get(e.rule_id) ?? "";
    await tx
      .insertInto("enforcement_events")
      .values({ id: newId(), org_id: device.org_id, device_id: device.id, rule_id: ruleId, rule_name: name, action: e.action, subject: e.subject, user_name: e.user, count: e.count, detail: e.detail, occurred_at: new Date(e.at) })
      .execute();
    await audit(tx, device.org_id, { meta }, {
      type: e.action === "terminated" ? "device.app_terminated" : e.action === "would_terminate" ? "device.app_would_terminate" : "device.enforcement_failed",
      outcome: e.action === "failed" ? "failure" : "success",
      actor: { type: "system", id: null, display: "Nexus agent" },
      target: { type: "device", id: device.id, display: device.hostname },
      details: { rule_id: ruleId, rule: name, subject: e.subject, user: e.user, count: e.count, detail: e.detail },
    });
  }
}

// ---- API ------------------------------------------------------------------------------------------

const RuleIn = z.object({
  name: z.string().trim().min(1).max(100),
  kind: Kind,
  match: Match,
  value: z.string().min(1).max(1000),
  mode: Mode.default("monitor"),
  target: Target.default({ all: true }),
  platforms: Platforms.default(["macos", "windows", "linux"]),
  reason: z.string().trim().max(500).default(""),
  enabled: z.boolean().default(true),
});
const RuleOut = z
  .object({
    id: Id,
    name: z.string(),
    kind: Kind,
    match: Match,
    value: z.string(),
    mode: Mode,
    target: z.object({ all: z.boolean().optional(), group_ids: z.array(z.string()).optional() }),
    platforms: z.array(z.string()),
    reason: z.string(),
    enabled: z.boolean(),
    created_by: z.string().nullable(),
    created_at: z.string(),
    updated_at: z.string(),
    stats: z.object({ devices: z.number().int(), events_7d: z.number().int() }),
  })
  .openapi("EnforcementRule");
const EventOut = z
  .object({
    id: Id,
    device_id: Id,
    hostname: z.string(),
    rule_id: z.string().nullable(),
    rule_name: z.string(),
    action: z.enum(["terminated", "would_terminate", "domain_blocked", "failed"]),
    subject: z.string(),
    user: z.string(),
    count: z.number().int(),
    detail: z.string(),
    occurred_at: z.string(),
  })
  .openapi("EnforcementEvent");

const ownHosts = (deps: Deps) => [deps.cfg.apiPublicUrl, deps.cfg.publicUrl].map((u) => new URL(u).hostname.toLowerCase());

async function listRules(tx: Tx, ids?: string[]) {
  let q = tx.selectFrom("enforcement_rules").leftJoin("users", "users.id", "enforcement_rules.created_by").selectAll("enforcement_rules").select("users.email").orderBy("enforcement_rules.created_at");
  if (ids) q = q.where("enforcement_rules.id", "in", ids);
  const rows = await q.execute();
  const since = new Date(Date.now() - 7 * 86_400_000);
  const stats = await tx
    .selectFrom("enforcement_events")
    .select(["rule_id", (eb) => eb.fn.count<number>("device_id").distinct().as("devices"), (eb) => eb.fn.sum<number>("count").as("events")])
    .where("occurred_at", ">", since)
    .groupBy("rule_id")
    .execute();
  const byRule = new Map(stats.map((s) => [s.rule_id, s]));
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    kind: r.kind,
    match: r.match,
    value: r.value,
    mode: r.mode,
    target: r.target,
    platforms: r.platforms,
    reason: r.reason,
    enabled: r.enabled,
    created_by: r.email,
    created_at: iso(r.created_at),
    updated_at: iso(r.updated_at),
    stats: { devices: Number(byRule.get(r.id)?.devices ?? 0), events_7d: Number(byRule.get(r.id)?.events ?? 0) },
  }));
}

export function registerEnforcementRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/enforcement/rules", tags: ["Devices"], summary: "App and domain block rules", security: bearer, responses: { 200: json(z.object({ data: z.array(RuleOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => listRules(tx)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/enforcement/rules",
      tags: ["Devices"],
      summary: "Add a block rule",
      description: "App rules terminate matching programs (monitor mode first reports what they'd stop); domain rules sinkhole a domain in the hosts file. Needs `devices:enforce` and a recent MFA.",
      security: bearer,
      request: body(RuleIn),
      responses: { 201: json(RuleOut, "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const checked = checkRule(input, ownHosts(deps));
      if ("error" in checked) throw badRequest("invalid_rule", checked.error);
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const count = await tx.selectFrom("enforcement_rules").select((eb) => eb.fn.countAll<number>().as("n")).executeTakeFirst();
        if (Number(count?.n ?? 0) >= MAX_RULES) throw badRequest("too_many_rules", `An organization can have at most ${MAX_RULES} rules`);
        const id = newId();
        await tx
          .insertInto("enforcement_rules")
          .values({ id, org_id: p.orgId, name: input.name, kind: input.kind, match: input.match, value: checked.value, mode: input.kind === "domain" ? "block" : input.mode, target: JSON.stringify(input.target), platforms: input.platforms, reason: input.reason, enabled: input.enabled, created_by: p.userId })
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "enforcement.rule_created", target: { type: "enforcement_rule", id, display: input.name }, details: { kind: input.kind, match: input.match, value: checked.value, mode: input.kind === "domain" ? "block" : input.mode, target: input.target, reason: input.reason } });
        return (await listRules(tx, [id]))[0]!;
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/enforcement/rules/{id}",
      tags: ["Devices"],
      summary: "Change a block rule (e.g. from monitor to block)",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(RuleIn.partial()) },
      responses: { 200: json(RuleOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const cur = await tx.selectFrom("enforcement_rules").selectAll().where("id", "=", id).executeTakeFirst();
        if (!cur) throw notFound("Rule");
        const next = { kind: input.kind ?? cur.kind, match: input.match ?? cur.match, value: input.value ?? cur.value };
        const checked = checkRule(next, ownHosts(deps));
        if ("error" in checked) throw badRequest("invalid_rule", checked.error);
        const mode = next.kind === "domain" ? "block" : (input.mode ?? cur.mode);
        await tx
          .updateTable("enforcement_rules")
          .set({
            ...(input.name !== undefined ? { name: input.name } : {}),
            kind: next.kind,
            match: next.match,
            value: checked.value,
            mode,
            ...(input.target ? { target: JSON.stringify(input.target) } : {}),
            ...(input.platforms ? { platforms: input.platforms } : {}),
            ...(input.reason !== undefined ? { reason: input.reason } : {}),
            ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
            updated_at: new Date(),
          })
          .where("id", "=", id)
          .execute();
        const changes = Object.fromEntries(Object.entries({ ...input, value: input.value !== undefined ? checked.value : undefined, mode: input.mode !== undefined ? mode : undefined }).filter(([, v]) => v !== undefined));
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "enforcement.rule_updated", target: { type: "enforcement_rule", id, display: input.name ?? cur.name }, details: { changes } });
        return (await listRules(tx, [id]))[0]!;
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/enforcement/rules/{id}", tags: ["Devices"], summary: "Remove a block rule", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const r = await tx.deleteFrom("enforcement_rules").where("id", "=", id).returning(["name", "kind", "value"]).executeTakeFirst();
        if (!r) throw notFound("Rule");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "enforcement.rule_deleted", target: { type: "enforcement_rule", id, display: r.name }, details: { kind: r.kind, value: r.value } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/enforcement/events",
      tags: ["Devices"],
      summary: "What devices blocked (or would have, in monitor mode)",
      security: bearer,
      request: { query: z.object({ device_id: Id.optional(), rule_id: Id.optional(), limit: z.coerce.number().int().min(1).max(500).default(100) }) },
      responses: { 200: json(z.object({ data: z.array(EventOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const q = c.req.valid("query");
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        if (q.device_id) await assertDeviceInScope(tx, p, "devices:read", q.device_id);
        else requirePermission(c, "devices:read"); // the fleet-wide list is for org-wide readers
        let query = tx.selectFrom("enforcement_events").innerJoin("devices", "devices.id", "enforcement_events.device_id").selectAll("enforcement_events").select("devices.hostname").orderBy("enforcement_events.occurred_at", "desc").limit(q.limit);
        if (q.device_id) query = query.where("enforcement_events.device_id", "=", q.device_id);
        if (q.rule_id) query = query.where("enforcement_events.rule_id", "=", q.rule_id);
        return query.execute();
      });
      return c.json(
        { data: rows.map((r) => ({ id: r.id, device_id: r.device_id, hostname: r.hostname, rule_id: r.rule_id, rule_name: r.rule_name, action: r.action, subject: r.subject, user: r.user_name, count: r.count, detail: r.detail, occurred_at: iso(r.occurred_at) })) },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/devices/{id}/enforcement",
      tags: ["Devices"],
      summary: "The block rules a device should enforce, and what it last reported",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: {
        200: json(
          z.object({
            rules: z.array(z.object({ id: Id, name: z.string(), kind: Kind, match: Match, value: z.string(), mode: Mode })),
            expected_version: z.string(),
            applied_version: z.string(),
            in_sync: z.boolean(),
            status: z.string(),
            last_seen_at: z.string().nullable(),
          }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertDeviceInScope(tx, p, "devices:read", id);
        const d = await tx.selectFrom("devices").select(["id", "platform", "primary_user_id", "enforcement_version", "enforcement_status", "last_seen_at"]).where("id", "=", id).executeTakeFirst();
        if (!d) throw notFound("Device");
        const rules = await rulesFor(tx, d);
        const expected = policyVersion(rules);
        return { rules, expected_version: expected, applied_version: d.enforcement_version, in_sync: d.enforcement_version === expected, status: d.enforcement_status, last_seen_at: isoOrNull(d.last_seen_at) };
      });
      return c.json(out, 200);
    },
  );
}

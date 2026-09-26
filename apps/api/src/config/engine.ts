import { createHash, randomBytes } from "node:crypto";
import { z } from "@hono/zod-openapi";
import type { Deps, Principal, RequestMeta } from "../context.js";
import { REQUIREMENTS } from "../access/engine.js";
import { BUILTIN_RULES, ensureBuiltins, SEVERITIES } from "../alerts/engine.js";
import { audit } from "../audit/record.js";
import { reevaluateAll, getPolicies } from "../devices/service.js";
import { CHECK_KEYS, PolicyParams } from "../devices/posture.js";
import { evaluateDynamicGroups } from "../directory/dynamic-groups.js";
import { RISKS } from "../mcp/policy.js";
import { serverAad } from "../mcp/service.js";
import { applySettings } from "../org/routes.js";
import { getSettings, OrgSettings } from "../org/settings.js";
import { canonical } from "../platform/canonical.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";
import { enqueue } from "../platform/jobs.js";
import { touchGroups, touchUsers } from "../provisioning/service.js";
import type { Permission } from "../rbac.js";
import { GroupRule } from "../schemas.js";

/**
 * Config as code (SPEC OPS-07, INT-05). An organization's policies as one
 * portable document that refers to things by name (groups, apps, people by
 * email, agents, MCP servers by slug), never by ID, so the same file can
 * promote staging to production. Plan and apply share one code path: a plan
 * is exactly what apply would do. Sections left out of a document are left
 * alone; items missing from a listed section are deleted only with `prune`.
 * Secrets never appear in exports.
 */

const Name = z.string().trim().min(1).max(100);

const Doc = z
  .object({
    version: z.literal(1),
    settings: OrgSettings.partial().optional(),
    groups: z.array(z.object({ name: Name, description: z.string().max(500).default(""), rule: z.union([GroupRule, z.null()]).default(null) })).optional(),
    conditional_access: z
      .array(
        z.object({
          name: Name,
          enabled: z.boolean().default(true),
          mode: z.enum(["report_only", "enforce"]).default("report_only"),
          requirement: z.enum(REQUIREMENTS),
          apps: z.union([z.literal("all"), z.array(Name).min(1)]).openapi({ description: "App names" }),
          users: z.object({
            include: z.union([z.literal("all"), z.object({ groups: z.array(Name).default([]), users: z.array(z.string().email()).default([]) })]),
            exclude: z.object({ groups: z.array(Name).default([]), users: z.array(z.string().email()).default([]) }).default({ groups: [], users: [] }),
          }),
        }),
      )
      .optional(),
    device_policies: z.array(z.object({ check: z.enum(CHECK_KEYS), enabled: z.boolean(), mode: z.enum(["audit", "enforce"]).default("enforce"), grace_hours: z.number().int().min(0).max(720).default(0), params: z.record(z.string(), z.unknown()).default({}) })).optional(),
    alert_rules: z
      .array(
        z.object({
          name: Name,
          builtin: z.string().max(50).optional().openapi({ description: "For a default rule: its key" }),
          description: z.string().max(500).default(""),
          enabled: z.boolean().default(true),
          severity: z.enum(SEVERITIES),
          match: z.object({ types: z.array(z.string().max(100)).min(1).max(20), outcome: z.enum(["success", "failure", "denied"]).optional(), details: z.record(z.string(), z.string()).optional() }),
          group_by: z.enum(["none", "actor", "target", "ip"]).default("none"),
          threshold: z.number().int().min(1).max(10000).default(1),
          window_minutes: z.number().int().min(1).max(1440).default(5),
        }),
      )
      .optional(),
    agents: z
      .array(
        z.object({
          name: Name,
          description: z.string().max(1000).default(""),
          owner: z.string().max(200).openapi({ description: "An email, or group:<name>" }),
          environment: z.enum(["production", "staging", "development"]).default("production"),
          runtime: z.string().max(100).default(""),
          model: z.string().max(100).default(""),
          risk_tier: z.enum(["low", "medium", "high", "critical"]).default("medium"),
          tags: z.array(z.string().max(50)).max(20).default([]),
          token_ttl_minutes: z.number().int().min(5).max(60).default(15),
        }),
      )
      .optional(),
    mcp_servers: z
      .array(
        z.object({
          slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,39}$/),
          name: Name,
          url: z.string().url().max(500),
          description: z.string().max(1000).default(""),
          auth: z
            .object({ kind: z.enum(["none", "bearer", "header"]), header: z.string().max(64).optional(), token: z.string().max(4000).optional(), token_env: z.string().max(100).optional().openapi({ description: "Read by the CLI; the API never sees it" }) })
            .default({ kind: "none" }),
          auto_approve_read: z.boolean().default(false),
          calls_per_minute: z.number().int().min(1).max(10000).default(120),
          status: z.enum(["active", "disabled"]).default("active"),
          permissions: z
            .array(
              z.object({
                effect: z.enum(["allow", "deny"]),
                subject: z.string().max(150).openapi({ description: "all_agents, agent:<name> or tag:<tag>" }),
                tools: z.array(z.string().max(128)).min(1),
                risks: z.array(z.enum(RISKS)).nullable().default(null),
                conditions: z.array(z.object({ argument: z.string().max(100), op: z.enum(["equals", "in", "not_in", "prefix"]), values: z.array(z.string().max(300)).min(1) })).default([]),
                description: z.string().max(500).default(""),
              }),
            )
            .default([]),
        }),
      )
      .optional(),
  })
  .openapi("OrgConfig");
export const ConfigDoc = Doc;
export type ConfigDoc = z.infer<typeof Doc>;

export const SECTION_PERMISSION: Record<Exclude<keyof ConfigDoc, "version">, Permission> = {
  settings: "org:manage",
  groups: "groups:write",
  conditional_access: "policies:write",
  device_policies: "devices:write",
  alert_rules: "alerts:manage",
  agents: "agents:manage",
  mcp_servers: "mcp:manage",
};

export type Change = { section: string; action: "create" | "update" | "delete"; key: string; changes?: Record<string, { from: unknown; to: unknown }> };
export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(problems.join("; "));
  }
}

function fieldDiff(before: Record<string, unknown>, after: Record<string, unknown>) {
  const out: Record<string, { from: unknown; to: unknown }> = {};
  for (const k of Object.keys(after)) if (canonical(before[k] ?? null) !== canonical(after[k] ?? null)) out[k] = { from: before[k] ?? null, to: after[k] ?? null };
  return out;
}

const dupes = (xs: string[]) => [...new Set(xs.filter((x, i) => xs.indexOf(x) !== i))];

// ---- Export --------------------------------------------------------------------------

export async function exportConfig(tx: Tx, orgId: string): Promise<ConfigDoc> {
  const users = new Map((await tx.selectFrom("users").select(["id", "email"]).execute()).map((u) => [u.id, u.email]));
  const groupRows = await tx.selectFrom("groups").select(["id", "name", "description", "rule"]).orderBy("name").execute();
  const linked = new Set((await tx.selectFrom("directory_links").select("local_id").where("kind", "=", "group").execute()).map((l) => l.local_id));
  const groups = new Map(groupRows.map((g) => [g.id, g.name]));
  const apps = new Map((await tx.selectFrom("applications").select(["id", "name"]).execute()).map((a) => [a.id, a.name]));
  const agents = await tx.selectFrom("ai_agents").selectAll().orderBy("name").execute();
  const agentNames = new Map(agents.map((a) => [a.id, a.name]));
  const servers = await tx.selectFrom("mcp_servers").selectAll().orderBy("slug").execute();
  const perms = await tx.selectFrom("mcp_permissions").selectAll().orderBy("created_at").execute();
  const policies = await tx.selectFrom("access_policies").selectAll().orderBy("created_at").execute();
  type Cond = { apps: "all" | string[]; users: { include: "all" | { groups: string[]; users: string[] }; exclude: { groups: string[]; users: string[] } } };
  return {
    version: 1,
    settings: await getSettings(tx, orgId),
    groups: groupRows.filter((g) => !linked.has(g.id)).map((g) => ({ name: g.name, description: g.description, rule: (g.rule as z.infer<typeof GroupRule> | null) ?? null })),
    conditional_access: policies.map((p) => {
      const c = p.conditions as unknown as Cond;
      const names = (ids: string[], m: Map<string, string>) => ids.map((i) => m.get(i) ?? i);
      return {
        name: p.name,
        enabled: p.enabled,
        mode: p.mode,
        requirement: p.requirement,
        apps: c.apps === "all" ? "all" : names(c.apps, apps),
        users: {
          include: c.users.include === "all" ? "all" : { groups: names(c.users.include.groups, groups), users: names(c.users.include.users, users) },
          exclude: { groups: names(c.users.exclude.groups, groups), users: names(c.users.exclude.users, users) },
        },
      };
    }),
    device_policies: (await getPolicies(tx)).map((p) => ({ check: p.key, enabled: p.enabled, mode: p.mode, grace_hours: p.grace_hours, params: p.params })),
    alert_rules: (await tx.selectFrom("alert_rules").selectAll().orderBy("name").execute()).map((r) => ({
      name: r.name,
      ...(r.builtin_key ? { builtin: r.builtin_key } : {}),
      description: r.description,
      enabled: r.enabled,
      severity: r.severity,
      match: r.match as unknown as NonNullable<ConfigDoc["alert_rules"]>[number]["match"],
      group_by: r.group_by,
      threshold: r.threshold,
      window_minutes: r.window_minutes,
    })),
    agents: agents.map((a) => ({
      name: a.name,
      description: a.description,
      owner: a.owner_user_id ? (users.get(a.owner_user_id) ?? "") : a.owner_group_id ? `group:${groups.get(a.owner_group_id) ?? ""}` : "",
      environment: a.environment,
      runtime: a.runtime,
      model: a.model,
      risk_tier: a.risk_tier,
      tags: a.tags,
      token_ttl_minutes: a.token_ttl_minutes,
    })),
    mcp_servers: servers.map((s) => ({
      slug: s.slug,
      name: s.name,
      url: s.url,
      description: s.description,
      auth: s.auth_kind === "none" ? { kind: "none" as const } : { kind: s.auth_kind, ...(s.auth_kind === "header" ? { header: s.auth_header } : {}), token_env: `NEXUS_MCP_${s.slug.toUpperCase().replace(/-/g, "_")}_TOKEN` },
      auto_approve_read: s.auto_approve_read,
      calls_per_minute: s.calls_per_minute,
      status: s.status,
      permissions: perms
        .filter((p) => p.server_id === s.id)
        .map((p) => ({
          effect: p.effect,
          subject: p.subject_type === "all_agents" ? "all_agents" : p.subject_type === "agent_tag" ? `tag:${p.subject_tag}` : `agent:${agentNames.get(p.subject_id!) ?? p.subject_id}`,
          tools: p.tools,
          risks: p.risks as NonNullable<ConfigDoc["mcp_servers"]>[number]["permissions"][number]["risks"],
          conditions: p.conditions as unknown as NonNullable<ConfigDoc["mcp_servers"]>[number]["permissions"][number]["conditions"],
          description: p.description,
        })),
    })),
  };
}

// ---- Plan / apply ----------------------------------------------------------------------

type Ctx = { tx: Tx; deps: Deps; p: Principal; meta: RequestMeta; apply: boolean; prune: boolean; changes: Change[]; problems: string[] };

const who = (c: Ctx) => ({ principal: c.p, meta: c.meta });
const viaConfig = { via: "config" };

async function syncSettings(c: Ctx, want: NonNullable<ConfigDoc["settings"]>) {
  const before = await getSettings(c.tx, c.p.orgId);
  const after = { ...before, ...want };
  const d = fieldDiff(before as unknown as Record<string, unknown>, after as unknown as Record<string, unknown>);
  if (!Object.keys(d).length) return;
  c.changes.push({ section: "settings", action: "update", key: "settings", changes: d });
  if (c.apply) await applySettings(c.tx, c.p, c.meta, before, after, "config");
}

async function syncGroups(c: Ctx, want: NonNullable<ConfigDoc["groups"]>) {
  for (const d of dupes(want.map((g) => g.name.toLowerCase()))) c.problems.push(`groups: "${d}" is listed twice`);
  const rows = await c.tx.selectFrom("groups").select(["id", "name", "description", "rule"]).execute();
  const linked = new Set((await c.tx.selectFrom("directory_links").select("local_id").where("kind", "=", "group").execute()).map((l) => l.local_id));
  const requestable = new Set((await c.tx.selectFrom("access_catalog").select("resource_id").where("resource_type", "=", "group").execute()).map((r) => r.resource_id));
  const byName = new Map(rows.map((r) => [r.name.toLowerCase(), r]));
  const dynamicChanged: string[] = [];
  for (const g of want) {
    const cur = byName.get(g.name.toLowerCase());
    if (!cur) {
      c.changes.push({ section: "groups", action: "create", key: g.name });
      if (c.apply) {
        const id = newId();
        await c.tx.insertInto("groups").values({ id, org_id: c.p.orgId, name: g.name, description: g.description, rule: g.rule ? JSON.stringify(g.rule) : null, updated_at: new Date() }).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "group.created", target: { type: "group", id, display: g.name }, details: { ...viaConfig, rule: g.rule } });
        if (g.rule) dynamicChanged.push(id);
      }
      continue;
    }
    if (linked.has(cur.id)) {
      c.problems.push(`groups: "${g.name}" is managed by a directory; leave it out of the config`);
      continue;
    }
    const d = fieldDiff({ description: cur.description, rule: cur.rule ?? null }, { description: g.description, rule: g.rule });
    if (!Object.keys(d).length) continue;
    if (d.rule && g.rule && requestable.has(cur.id)) c.problems.push(`groups: "${g.name}" is requestable in the access catalog, so it can't have a rule`);
    c.changes.push({ section: "groups", action: "update", key: g.name, changes: d });
    if (c.apply) {
      await c.tx.updateTable("groups").set({ description: g.description, rule: g.rule ? JSON.stringify(g.rule) : null, updated_at: new Date() }).where("id", "=", cur.id).execute();
      await audit(c.tx, c.p.orgId, who(c), { type: "group.updated", target: { type: "group", id: cur.id, display: cur.name }, details: { ...viaConfig, changes: d } });
      if (g.rule) dynamicChanged.push(cur.id);
    }
  }
  if (c.prune) {
    const keep = new Set(want.map((g) => g.name.toLowerCase()));
    for (const r of rows.filter((x) => !keep.has(x.name.toLowerCase()) && !linked.has(x.id))) {
      c.changes.push({ section: "groups", action: "delete", key: r.name });
      if (c.apply) {
        const members = await c.tx.selectFrom("group_members").select("user_id").where("group_id", "=", r.id).execute();
        await c.tx.deleteFrom("groups").where("id", "=", r.id).execute();
        await c.tx.deleteFrom("app_assignments").where("principal_type", "=", "group").where("principal_id", "=", r.id).execute();
        await touchUsers(c.tx, c.p.orgId, members.map((m) => m.user_id));
        await touchGroups(c.tx, c.p.orgId, [r.id]);
        await audit(c.tx, c.p.orgId, who(c), { type: "group.deleted", target: { type: "group", id: r.id, display: r.name }, details: viaConfig });
      }
    }
  }
  if (c.apply) for (const id of dynamicChanged) await evaluateDynamicGroups(c.tx, c.p.orgId, c.meta, id);
}

async function resolver(c: Ctx, doc: ConfigDoc) {
  const groups = new Map((await c.tx.selectFrom("groups").select(["id", "name"]).execute()).map((g) => [g.name.toLowerCase(), g.id]));
  for (const g of doc.groups ?? []) if (!groups.has(g.name.toLowerCase())) groups.set(g.name.toLowerCase(), `(new group ${g.name})`);
  const users = new Map((await c.tx.selectFrom("users").select(["id", "email"]).where("status", "<>", "deprovisioned").execute()).map((u) => [u.email.toLowerCase(), u.id]));
  const apps = new Map((await c.tx.selectFrom("applications").select(["id", "name"]).execute()).map((a) => [a.name.toLowerCase(), a.id]));
  const need = (m: Map<string, string>, what: string, where: string) => (n: string) => {
    const id = m.get(n.toLowerCase());
    if (!id) c.problems.push(`${where}: unknown ${what} "${n}"`);
    return id ?? "";
  };
  return { groups, users, apps, need };
}

async function syncConditionalAccess(c: Ctx, doc: ConfigDoc, want: NonNullable<ConfigDoc["conditional_access"]>) {
  for (const d of dupes(want.map((x) => x.name.toLowerCase()))) c.problems.push(`conditional_access: "${d}" is listed twice`);
  const r = await resolver(c, doc);
  const rows = await c.tx.selectFrom("access_policies").selectAll().execute();
  const byName = new Map(rows.map((x) => [x.name.toLowerCase(), x]));
  for (const w of want) {
    const where = `conditional_access "${w.name}"`;
    const g = r.need(r.groups, "group", where);
    const u = r.need(r.users, "person", where);
    const conditions = {
      apps: w.apps === "all" ? "all" : w.apps.map(r.need(r.apps, "app", where)),
      users: {
        include: w.users.include === "all" ? "all" : { groups: w.users.include.groups.map(g), users: w.users.include.users.map(u) },
        exclude: { groups: w.users.exclude.groups.map(g), users: w.users.exclude.users.map(u) },
      },
    };
    const desired = { enabled: w.enabled, mode: w.mode, requirement: w.requirement, conditions };
    const cur = byName.get(w.name.toLowerCase());
    if (!cur) {
      c.changes.push({ section: "conditional_access", action: "create", key: w.name });
      if (c.apply) {
        const id = newId();
        await c.tx.insertInto("access_policies").values({ id, org_id: c.p.orgId, name: w.name, ...desired, conditions: JSON.stringify(conditions), updated_at: new Date() }).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "access.policy_created", target: { type: "access_policy", id, display: w.name }, details: { ...viaConfig, ...desired } });
      }
      continue;
    }
    const d = fieldDiff({ enabled: cur.enabled, mode: cur.mode, requirement: cur.requirement, conditions: cur.conditions }, desired);
    if (!Object.keys(d).length) continue;
    c.changes.push({ section: "conditional_access", action: "update", key: w.name, changes: d });
    if (c.apply) {
      await c.tx.updateTable("access_policies").set({ ...desired, conditions: JSON.stringify(conditions), updated_at: new Date() }).where("id", "=", cur.id).execute();
      await audit(c.tx, c.p.orgId, who(c), { type: "access.policy_updated", target: { type: "access_policy", id: cur.id, display: cur.name }, details: { ...viaConfig, changes: d } });
    }
  }
  if (c.prune) {
    const keep = new Set(want.map((x) => x.name.toLowerCase()));
    for (const x of rows.filter((y) => !keep.has(y.name.toLowerCase()))) {
      c.changes.push({ section: "conditional_access", action: "delete", key: x.name });
      if (c.apply) {
        await c.tx.deleteFrom("access_policies").where("id", "=", x.id).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "access.policy_deleted", target: { type: "access_policy", id: x.id, display: x.name }, details: viaConfig });
      }
    }
  }
}

async function syncDevicePolicies(c: Ctx, want: NonNullable<ConfigDoc["device_policies"]>) {
  for (const d of dupes(want.map((x) => x.check))) c.problems.push(`device_policies: "${d}" is listed twice`);
  const current = new Map((await getPolicies(c.tx)).map((p) => [p.key, p]));
  let changed = false;
  for (const w of want) {
    const params = PolicyParams[w.check].safeParse({ ...(current.get(w.check)?.params ?? {}), ...w.params });
    if (!params.success) {
      c.problems.push(`device_policies "${w.check}": ${params.error.issues.map((i) => `${i.path.join(".")} ${i.message}`).join(", ")}`);
      continue;
    }
    const cur = current.get(w.check)!;
    const desired = { enabled: w.enabled, mode: w.mode, grace_hours: w.grace_hours, params: params.data as Record<string, unknown> };
    const d = fieldDiff({ enabled: cur.enabled, mode: cur.mode, grace_hours: cur.grace_hours, params: cur.params }, desired);
    if (!Object.keys(d).length) continue;
    c.changes.push({ section: "device_policies", action: "update", key: w.check, changes: d });
    if (c.apply) {
      const row = { ...desired, params: JSON.stringify(desired.params), updated_at: new Date() };
      await c.tx.insertInto("device_policies").values({ org_id: c.p.orgId, check_key: w.check, ...row }).onConflict((oc) => oc.columns(["org_id", "check_key"]).doUpdateSet(row)).execute();
      await audit(c.tx, c.p.orgId, who(c), { type: "device.policy_updated", target: { type: "device_policy", id: null, display: w.check }, details: { ...viaConfig, key: w.check, changes: d } });
      changed = true;
    }
  }
  if (changed) await reevaluateAll(c.tx, { meta: c.meta });
}

async function syncAlertRules(c: Ctx, want: NonNullable<ConfigDoc["alert_rules"]>) {
  await ensureBuiltins(c.tx, c.p.orgId);
  for (const d of dupes(want.map((x) => (x.builtin ?? x.name).toLowerCase()))) c.problems.push(`alert_rules: "${d}" is listed twice`);
  const rows = await c.tx.selectFrom("alert_rules").selectAll().execute();
  const keyOf = (r: { builtin_key?: string | null; builtin?: string; name: string }) => ((r as { builtin_key?: string | null }).builtin_key ?? (r as { builtin?: string }).builtin ?? `name:${r.name.toLowerCase()}`) as string;
  const byKey = new Map(rows.map((r) => [r.builtin_key ?? `name:${r.name.toLowerCase()}`, r]));
  for (const w of want) {
    if (w.builtin && !BUILTIN_RULES.some((b) => b.key === w.builtin)) {
      c.problems.push(`alert_rules: unknown default rule "${w.builtin}"`);
      continue;
    }
    const cur = byKey.get(keyOf(w));
    const desired = { name: w.name, description: w.description, enabled: w.enabled, severity: w.severity, match: w.match, group_by: w.group_by, threshold: w.threshold, window_minutes: w.window_minutes };
    if (!cur) {
      c.changes.push({ section: "alert_rules", action: "create", key: w.name });
      if (c.apply) {
        const id = newId();
        await c.tx.insertInto("alert_rules").values({ id, org_id: c.p.orgId, ...desired, match: JSON.stringify(w.match), created_by: c.p.apiKey ? null : c.p.userId }).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "alert.rule_created", target: { type: "alert_rule", id, display: w.name }, details: { ...viaConfig, ...desired } });
      }
      continue;
    }
    const d = fieldDiff({ name: cur.name, description: cur.description, enabled: cur.enabled, severity: cur.severity, match: cur.match, group_by: cur.group_by, threshold: cur.threshold, window_minutes: cur.window_minutes }, desired);
    if (!Object.keys(d).length) continue;
    c.changes.push({ section: "alert_rules", action: "update", key: w.name, changes: d });
    if (c.apply) {
      await c.tx.updateTable("alert_rules").set({ ...desired, match: JSON.stringify(w.match), updated_at: new Date() }).where("id", "=", cur.id).execute();
      await audit(c.tx, c.p.orgId, who(c), { type: "alert.rule_changed", target: { type: "alert_rule", id: cur.id, display: cur.name }, details: { ...viaConfig, changes: d } });
    }
  }
  if (c.prune) {
    const keep = new Set(want.map(keyOf));
    for (const r of rows.filter((x) => !x.builtin_key && !keep.has(`name:${x.name.toLowerCase()}`))) {
      c.changes.push({ section: "alert_rules", action: "delete", key: r.name });
      if (c.apply) {
        await c.tx.deleteFrom("alert_rules").where("id", "=", r.id).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "alert.rule_deleted", target: { type: "alert_rule", id: r.id, display: r.name }, details: viaConfig });
      }
    }
  }
}

async function syncAgents(c: Ctx, doc: ConfigDoc, want: NonNullable<ConfigDoc["agents"]>) {
  for (const d of dupes(want.map((x) => x.name.toLowerCase()))) c.problems.push(`agents: "${d}" is listed twice`);
  const r = await resolver(c, doc);
  const active = new Set((await c.tx.selectFrom("users").select("id").where("status", "=", "active").execute()).map((u) => u.id));
  const rows = await c.tx.selectFrom("ai_agents").selectAll().execute();
  const byName = new Map(rows.map((x) => [x.name.toLowerCase(), x]));
  for (const w of want) {
    const where = `agent "${w.name}"`;
    let owner = { owner_user_id: null as string | null, owner_group_id: null as string | null };
    if (w.owner.startsWith("group:")) owner.owner_group_id = r.need(r.groups, "group", where)(w.owner.slice(6)) || null;
    else {
      owner.owner_user_id = r.need(r.users, "person", where)(w.owner) || null;
      if (owner.owner_user_id && !active.has(owner.owner_user_id)) c.problems.push(`${where}: the owner ${w.owner} isn't active`);
    }
    if (owner.owner_group_id?.startsWith("(new")) owner = { ...owner, owner_group_id: null };
    const tags = w.tags.map((t) => t.toLowerCase());
    const desired = { description: w.description, environment: w.environment, runtime: w.runtime, model: w.model, risk_tier: w.risk_tier, tags, token_ttl_minutes: w.token_ttl_minutes, ...owner };
    const cur = byName.get(w.name.toLowerCase());
    if (!cur) {
      c.changes.push({ section: "agents", action: "create", key: w.name });
      if (c.apply) {
        if (w.owner.startsWith("group:") && !desired.owner_group_id) desired.owner_group_id = (await c.tx.selectFrom("groups").select("id").where("name", "=", w.owner.slice(6)).executeTakeFirst())?.id ?? null;
        const id = newId();
        await c.tx.insertInto("ai_agents").values({ id, org_id: c.p.orgId, name: w.name, ...desired, client_id: `agt_${randomBytes(12).toString("base64url")}`, created_by: c.p.apiKey ? null : c.p.userId, updated_at: new Date() }).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "agent.registered", target: { type: "agent", id, display: w.name }, details: { ...viaConfig, ...desired } });
      }
      continue;
    }
    const d = fieldDiff({ description: cur.description, environment: cur.environment, runtime: cur.runtime, model: cur.model, risk_tier: cur.risk_tier, tags: cur.tags, token_ttl_minutes: cur.token_ttl_minutes, owner_user_id: cur.owner_user_id, owner_group_id: cur.owner_group_id }, desired);
    if (!Object.keys(d).length) continue;
    c.changes.push({ section: "agents", action: "update", key: w.name, changes: d });
    if (c.apply) {
      await c.tx.updateTable("ai_agents").set({ ...desired, updated_at: new Date() }).where("id", "=", cur.id).execute();
      await audit(c.tx, c.p.orgId, who(c), { type: "agent.updated", target: { type: "agent", id: cur.id, display: cur.name }, details: { ...viaConfig, changes: d } });
    }
  }
  if (c.prune) {
    const keep = new Set(want.map((x) => x.name.toLowerCase()));
    for (const a of rows.filter((x) => !keep.has(x.name.toLowerCase()))) {
      c.changes.push({ section: "agents", action: "delete", key: a.name });
      if (c.apply) {
        await c.tx.deleteFrom("ai_agents").where("id", "=", a.id).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "agent.deleted", target: { type: "agent", id: a.id, display: a.name }, details: viaConfig });
      }
    }
  }
}

async function syncMcpServers(c: Ctx, doc: ConfigDoc, want: NonNullable<ConfigDoc["mcp_servers"]>) {
  const declared = new Set((doc.agents ?? []).map((a) => a.name.toLowerCase()));
  for (const d of dupes(want.map((x) => x.slug))) c.problems.push(`mcp_servers: "${d}" is listed twice`);
  const rows = await c.tx.selectFrom("mcp_servers").selectAll().execute();
  const bySlug = new Map(rows.map((x) => [x.slug, x]));
  const agents = new Map((await c.tx.selectFrom("ai_agents").select(["id", "name"]).execute()).map((a) => [a.name.toLowerCase(), a.id]));
  const perms = await c.tx.selectFrom("mcp_permissions").selectAll().execute();
  const toSync: string[] = [];
  for (const w of want) {
    const where = `mcp_servers "${w.slug}"`;
    // Permissions, with subjects resolved.
    const wantPerms = w.permissions.map((p) => {
      let subject = { subject_type: "all_agents" as "all_agents" | "agent" | "agent_tag", subject_id: null as string | null, subject_tag: null as string | null };
      if (p.subject.startsWith("agent:")) {
        const n = p.subject.slice(6).toLowerCase();
        const id = agents.get(n) ?? (!c.apply && declared.has(n) ? "(new agent)" : undefined);
        if (!id) c.problems.push(`${where}: unknown agent "${p.subject.slice(6)}"`);
        subject = { subject_type: "agent", subject_id: id ?? null, subject_tag: null };
      } else if (p.subject.startsWith("tag:")) subject = { subject_type: "agent_tag", subject_id: null, subject_tag: p.subject.slice(4).toLowerCase() };
      else if (p.subject !== "all_agents") c.problems.push(`${where}: subject must be all_agents, agent:<name> or tag:<tag>, not "${p.subject}"`);
      return { effect: p.effect, ...subject, tools: p.tools, risks: p.risks, conditions: p.conditions, description: p.description };
    });
    const cur = bySlug.get(w.slug);
    const secretGiven = w.auth.kind !== "none" && !!w.auth.token;
    if (w.auth.kind !== "none" && !secretGiven && (!cur || cur.auth_kind !== w.auth.kind)) c.problems.push(`${where}: auth needs a token (set ${w.auth.token_env ?? "token_env"} for the CLI)`);
    const desired = { name: w.name, url: w.url, description: w.description, auto_approve_read: w.auto_approve_read, calls_per_minute: w.calls_per_minute, status: w.status, auth_kind: w.auth.kind, auth_header: w.auth.kind === "header" ? (w.auth.header ?? "") : "" };
    const seal = (id: string) => (w.auth.kind === "none" ? { secret: null } : secretGiven ? { secret: c.deps.sealer.seal(Buffer.from(w.auth.token!), serverAad(id)) } : {});
    let serverId = cur?.id;
    if (!cur) {
      c.changes.push({ section: "mcp_servers", action: "create", key: w.slug });
      if (c.apply) {
        serverId = newId();
        await c.tx.insertInto("mcp_servers").values({ id: serverId, org_id: c.p.orgId, slug: w.slug, ...desired, secret: null, ...seal(serverId), created_by: c.p.apiKey ? null : c.p.userId, updated_at: new Date() }).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "mcp.server_registered", target: { type: "mcp_server", id: serverId, display: w.name }, details: { ...viaConfig, url: w.url, slug: w.slug, auth: w.auth.kind } });
        toSync.push(serverId);
      }
    } else {
      const d = fieldDiff({ name: cur.name, url: cur.url, description: cur.description, auto_approve_read: cur.auto_approve_read, calls_per_minute: cur.calls_per_minute, status: cur.status, auth_kind: cur.auth_kind, auth_header: cur.auth_header }, desired);
      // A token that matches the stored one isn't a change (re-applying the same file is a no-op).
      const same = secretGiven && !!cur.secret && (() => {
        try {
          return c.deps.sealer.open(cur.secret!, serverAad(cur.id)).toString() === w.auth.token;
        } catch {
          return false;
        }
      })();
      if (secretGiven && !same) d.secret = { from: "(sealed)", to: "(new secret)" };
      if (Object.keys(d).length) {
        c.changes.push({ section: "mcp_servers", action: "update", key: w.slug, changes: d });
        if (c.apply) {
          await c.tx.updateTable("mcp_servers").set({ ...desired, ...seal(cur.id), updated_at: new Date() }).where("id", "=", cur.id).execute();
          await audit(c.tx, c.p.orgId, who(c), { type: "mcp.server_updated", target: { type: "mcp_server", id: cur.id, display: cur.name }, details: { ...viaConfig, changes: { ...d, ...(d.secret ? { secret: "(replaced)" } : {}) } } });
          if (d.url || d.secret || d.auth_kind) toSync.push(cur.id);
        }
      }
    }
    // Permissions are a set per server: replaced together when they differ.
    const norm = (xs: Record<string, unknown>[]) => xs.map((x) => canonical({ ...x, subject_id: x.subject_type === "agent" ? x.subject_id : null })).sort();
    const have = cur ? perms.filter((p) => p.server_id === cur.id).map((p) => ({ effect: p.effect, subject_type: p.subject_type, subject_id: p.subject_id, subject_tag: p.subject_tag, tools: p.tools, risks: p.risks, conditions: p.conditions, description: p.description })) : [];
    if (canonical(norm(have)) !== canonical(norm(wantPerms))) {
      c.changes.push({ section: "mcp_servers", action: "update", key: `${w.slug} permissions`, changes: { permissions: { from: have.length, to: wantPerms.length } } });
      if (c.apply && serverId) {
        await c.tx.deleteFrom("mcp_permissions").where("server_id", "=", serverId).execute();
        if (wantPerms.length) await c.tx.insertInto("mcp_permissions").values(wantPerms.map((p) => ({ id: newId(), org_id: c.p.orgId, server_id: serverId!, ...p, conditions: JSON.stringify(p.conditions), created_by: c.p.apiKey ? null : c.p.userId }))).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "mcp.permission_changed", target: { type: "mcp_server", id: serverId, display: w.name }, details: { ...viaConfig, permissions: wantPerms.length } });
      }
    }
  }
  if (c.prune) {
    const keep = new Set(want.map((x) => x.slug));
    for (const s of rows.filter((x) => !keep.has(x.slug))) {
      c.changes.push({ section: "mcp_servers", action: "delete", key: s.slug });
      if (c.apply) {
        await c.tx.deleteFrom("mcp_servers").where("id", "=", s.id).execute();
        await audit(c.tx, c.p.orgId, who(c), { type: "mcp.server_removed", target: { type: "mcp_server", id: s.id, display: s.name }, details: viaConfig });
      }
    }
  }
  if (c.apply) for (const id of toSync) await enqueue(c.tx, c.p.orgId, "mcp.sync", { server_id: id }, { dedupeKey: `mcp.sync:${id}` });
}

export const planHash = (changes: Change[]) => createHash("sha256").update(canonical(changes)).digest("hex").slice(0, 16);

/** Plans (and with apply, performs) the changes that make the org match the document. */
export async function reconcile(tx: Tx, deps: Deps, p: Principal, meta: RequestMeta, doc: ConfigDoc, opts: { apply: boolean; prune: boolean }) {
  const c: Ctx = { tx, deps, p, meta, apply: opts.apply, prune: opts.prune, changes: [], problems: [] };
  // Order matters: groups and agents exist before things that refer to them.
  if (doc.settings) await syncSettings(c, doc.settings);
  if (doc.groups) await syncGroups(c, doc.groups);
  if (doc.conditional_access) await syncConditionalAccess(c, doc, doc.conditional_access);
  if (doc.device_policies) await syncDevicePolicies(c, doc.device_policies);
  if (doc.alert_rules) await syncAlertRules(c, doc.alert_rules);
  if (doc.agents) await syncAgents(c, doc, doc.agents);
  if (doc.mcp_servers) await syncMcpServers(c, doc, doc.mcp_servers);
  if (c.problems.length) throw new ConfigError(c.problems);
  return { changes: c.changes, plan_id: planHash(c.changes) };
}

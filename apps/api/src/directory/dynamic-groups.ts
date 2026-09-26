import type { z } from "@hono/zod-openapi";
import { sql, type RawBuilder } from "kysely";
import type { Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import type { Tx } from "../platform/db.js";
import { enqueue, registerJobHandler, type JobRunner } from "../platform/jobs.js";
import { touchGroups, touchUsers } from "../provisioning/service.js";
import { RULE_ATTRIBUTES, GroupRule as Rule, GroupRuleCondition as Condition } from "../schemas.js";

type Rule = z.infer<typeof Rule>;

/**
 * Dynamic groups (DIR-05): a group whose members are everyone matching a rule
 * on their attributes. Rules compile to parameterised SQL. Membership is
 * re-evaluated when people change (debounced per organization) and every 15
 * minutes as a safety net; changes flow to app provisioning like manual ones.
 */


const like = (s: string) => s.toLowerCase().replace(/[\\%_]/g, (c) => `\\${c}`);

function column(attr: (typeof RULE_ATTRIBUTES)[number]): RawBuilder<string> {
  switch (attr) {
    case "email":
      return sql<string>`lower(u.email)`;
    case "email_domain":
      return sql<string>`split_part(lower(u.email), '@', 2)`;
    case "manager_id":
      return sql<string>`coalesce(u.manager_id::text, '')`;
    case "source":
      return sql<string>`coalesce((SELECT dc.provider FROM directory_links dl JOIN directory_connections dc ON dc.id = dl.connection_id WHERE dl.kind = 'user' AND dl.local_id = u.id LIMIT 1), 'none')`;
    default:
      return sql<string>`lower(coalesce(${sql.ref(`u.${attr}`)}, ''))`;
  }
}

function condition(c: z.infer<typeof Condition>): RawBuilder<boolean> {
  const col = column(c.attribute);
  const v = (c.value ?? "").toLowerCase();
  switch (c.op) {
    case "equals":
      return sql<boolean>`${col} = ${v}`;
    case "not_equals":
      return sql<boolean>`${col} <> ${v}`;
    case "contains":
      return sql<boolean>`${col} LIKE ${`%${like(v)}%`}`;
    case "starts_with":
      return sql<boolean>`${col} LIKE ${`${like(v)}%`}`;
    case "ends_with":
      return sql<boolean>`${col} LIKE ${`%${like(v)}`}`;
    case "in":
      return sql<boolean>`${col} = ANY(${(c.values ?? []).map((x) => x.toLowerCase())}::text[])`;
    case "is_empty":
      return sql<boolean>`${col} = ''`;
    case "is_not_empty":
      return sql<boolean>`${col} <> ''`;
  }
}

/** The SQL predicate for a rule, over users aliased u. */
export function predicate(rule: Rule): RawBuilder<boolean> {
  const parts = rule.conditions.map(condition);
  return sql<boolean>`(${sql.join(parts, rule.match === "all" ? sql` AND ` : sql` OR `)})`;
}

/** Everyone the rule matches: current people (not deprovisioned), never break-glass accounts. */
export async function matchingUsers(tx: Tx, rule: Rule, limit?: number) {
  const rows = await sql<{ id: string; email: string; given_name: string; family_name: string; department: string; title: string }>`
    SELECT u.id, u.email, u.given_name, u.family_name, u.department, u.title FROM users u
    WHERE u.status <> 'deprovisioned' AND NOT u.break_glass AND ${predicate(rule)}
    ORDER BY u.email ${limit ? sql`LIMIT ${limit}` : sql``}`.execute(tx);
  return rows.rows;
}

export async function countMatching(tx: Tx, rule: Rule) {
  return Number((await sql<{ n: number }>`SELECT count(*)::int AS n FROM users u WHERE u.status <> 'deprovisioned' AND NOT u.break_glass AND ${predicate(rule)}`.execute(tx)).rows[0]!.n);
}

/** Brings dynamic groups' members in line with their rules. Returns how many memberships changed. */
export async function evaluateDynamicGroups(tx: Tx, orgId: string, meta: RequestMeta, onlyGroupId?: string) {
  let q = tx.selectFrom("groups").select(["id", "name", "rule"]).where("rule", "is not", null);
  if (onlyGroupId) q = q.where("id", "=", onlyGroupId);
  let changed = 0;
  for (const g of await q.execute()) {
    const rule = Rule.safeParse(g.rule);
    if (!rule.success) continue;
    const want = new Set((await matchingUsers(tx, rule.data)).map((u) => u.id));
    const have = new Set((await tx.selectFrom("group_members").select("user_id").where("group_id", "=", g.id).execute()).map((m) => m.user_id));
    const add = [...want].filter((x) => !have.has(x));
    const remove = [...have].filter((x) => !want.has(x));
    if (add.length) await tx.insertInto("group_members").values(add.map((user_id) => ({ org_id: orgId, group_id: g.id, user_id }))).onConflict((oc) => oc.doNothing()).execute();
    if (remove.length) await tx.deleteFrom("group_members").where("group_id", "=", g.id).where("user_id", "in", remove).execute();
    await tx.updateTable("groups").set({ rule_evaluated_at: new Date() }).where("id", "=", g.id).execute();
    if (add.length || remove.length) {
      changed += add.length + remove.length;
      await touchUsers(tx, orgId, [...add, ...remove], undefined, { fromDynamicGroups: true });
      await touchGroups(tx, orgId, [g.id]);
      await audit(tx, orgId, { meta }, {
        type: "group.dynamic_updated",
        actor: { type: "system", id: null, display: "Dynamic group rule" },
        target: { type: "group", id: g.id, display: g.name },
        details: { added: add.length, removed: remove.length, added_ids: add.slice(0, 50), removed_ids: remove.slice(0, 50) },
      });
    }
  }
  return changed;
}

const SYSTEM: RequestMeta = { ip: "", userAgent: "nexus-dynamic-groups", requestId: "" };

registerJobHandler("groups.dynamic", async (deps, job) => {
  await deps.db.tenant(job.org_id, (tx) => evaluateDynamicGroups(tx, job.org_id, { ...SYSTEM, requestId: job.id }));
});

/** Every 15 minutes, as a safety net for changes that didn't go through touchUsers. */
export function scheduleDynamicGroups(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 15 * 60_000) return;
    last = Date.now();
    const orgs = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_orgs_with_dynamic_groups()`.execute(tx)).rows);
    for (const o of orgs) await deps.db.tenant(o.org_id, (tx) => enqueue(tx, o.org_id, "groups.dynamic", {}, { dedupeKey: "groups.dynamic" }));
  });
}

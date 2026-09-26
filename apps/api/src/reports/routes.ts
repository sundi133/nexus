import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission } from "../auth/guard.js";
import { authorize, type Condition, type Rule, type Tool } from "../mcp/policy.js";
import { toCsv } from "../platform/csv.js";
import type { Tx } from "../platform/db.js";
import { bearer, json, problemResponses } from "../schemas.js";

/**
 * Compliance reports (SPEC AUD-06): the evidence auditors ask for, as JSON or
 * CSV. Each report is computed live from current state; generating one is
 * audited, since reports export personal data.
 */

type Cell = string | number | boolean | null;
type Report = { title: string; description: string; summary: Record<string, number | string>; columns: string[]; rows: Cell[][] };

const KINDS = ["mfa_coverage", "admin_access", "dormant_accounts", "device_compliance", "app_access", "agent_tool_access"] as const;
type Kind = (typeof KINDS)[number];

const TITLES: Record<Kind, [string, string]> = {
  mfa_coverage: ["MFA coverage", "Every active person and the second factors they have."],
  admin_access: ["Admin access", "Everyone with an admin role, and how they sign in."],
  dormant_accounts: ["Dormant accounts", "Active accounts that haven't signed in for a while."],
  device_compliance: ["Device compliance", "Every enrolled device, its compliance and failing checks."],
  app_access: ["App access", "Who can sign in to which app, and why."],
  agent_tool_access: ["Agent tool access", "Which AI agents can call which MCP tools."],
};

const iso = (d: Date | null) => (d ? d.toISOString() : null);
const name = (u: { given_name: string; family_name: string; email: string }) => `${u.given_name} ${u.family_name}`.trim() || u.email;

async function factorsByUser(tx: Tx) {
  const rows = await tx.selectFrom("auth_factors").select(["user_id", "type"]).where("verified_at", "is not", null).execute();
  const m = new Map<string, Set<string>>();
  for (const r of rows) (m.get(r.user_id) ?? m.set(r.user_id, new Set()).get(r.user_id)!).add(r.type === "webauthn" ? "passkey" : r.type);
  return m;
}

async function build(tx: Tx, kind: Kind, days: number): Promise<Omit<Report, "title" | "description">> {
  switch (kind) {
    case "mfa_coverage": {
      const users = await tx.selectFrom("users").select(["id", "email", "given_name", "family_name", "last_login_at", "break_glass"]).where("status", "=", "active").orderBy("email").execute();
      const f = await factorsByUser(tx);
      const rows = users.map((u) => {
        const m = [...(f.get(u.id) ?? [])].sort();
        return [name(u), u.email, m.length > 0, m.includes("passkey"), m.join(" "), u.break_glass, iso(u.last_login_at)] as Cell[];
      });
      const withMfa = rows.filter((r) => r[2]).length;
      return {
        summary: { people: users.length, with_mfa: withMfa, without_mfa: users.length - withMfa, with_passkey: rows.filter((r) => r[3]).length, coverage_percent: users.length ? Math.round((withMfa / users.length) * 1000) / 10 : 100 },
        columns: ["name", "email", "mfa", "passkey", "methods", "break_glass", "last_sign_in"],
        rows,
      };
    }
    case "admin_access": {
      const rows = await tx
        .selectFrom("user_roles")
        .innerJoin("users", "users.id", "user_roles.user_id")
        .select(["users.id", "users.email", "users.given_name", "users.family_name", "users.status", "users.last_login_at", "users.break_glass", sql<string>`string_agg(user_roles.role, ' ' ORDER BY user_roles.role)`.as("roles"), sql<Date>`min(user_roles.created_at)`.as("since")])
        .groupBy(["users.id"])
        .orderBy("users.email")
        .execute();
      const f = await factorsByUser(tx);
      return {
        summary: { admins: rows.length, owners: rows.filter((r) => r.roles.split(" ").includes("owner")).length, without_mfa: rows.filter((r) => !f.get(r.id)?.size).length, break_glass: rows.filter((r) => r.break_glass).length },
        columns: ["name", "email", "roles", "status", "mfa_methods", "break_glass", "admin_since", "last_sign_in"],
        rows: rows.map((r) => [name(r), r.email, r.roles, r.status, [...(f.get(r.id) ?? [])].sort().join(" "), r.break_glass, iso(r.since), iso(r.last_login_at)]),
      };
    }
    case "dormant_accounts": {
      const cutoff = new Date(Date.now() - days * 86_400_000);
      const rows = await tx
        .selectFrom("users")
        .select(["email", "given_name", "family_name", "last_login_at", "created_at", "department", "break_glass"])
        .where("status", "=", "active")
        .where((eb) => eb.or([eb("last_login_at", "<", cutoff), eb.and([eb("last_login_at", "is", null), eb("created_at", "<", cutoff)])]))
        .orderBy("last_login_at", "asc")
        .execute();
      return {
        summary: { dormant: rows.length, days },
        columns: ["name", "email", "department", "last_sign_in", "created", "break_glass"],
        rows: rows.map((r) => [name(r), r.email, r.department, iso(r.last_login_at), iso(r.created_at), r.break_glass]),
      };
    }
    case "device_compliance": {
      const devices = await tx
        .selectFrom("devices")
        .leftJoin("users", "users.id", "devices.primary_user_id")
        .select(["devices.id", "devices.hostname", "devices.platform", "devices.os_name", "devices.os_version", "devices.serial", "devices.compliance", "devices.compliance_grace_until", "devices.last_seen_at", "users.email"])
        .where("devices.status", "=", "active")
        .orderBy("devices.hostname")
        .execute();
      const failing = await tx.selectFrom("device_checks").select(["device_id", "check_key", "enforced"]).where("status", "=", "fail").execute();
      const byDevice = new Map<string, string[]>();
      for (const f of failing) (byDevice.get(f.device_id) ?? byDevice.set(f.device_id, []).get(f.device_id)!).push(f.enforced ? f.check_key : `${f.check_key} (audit)`);
      const count = (c: string) => devices.filter((d) => d.compliance === c).length;
      return {
        summary: { devices: devices.length, compliant: count("compliant"), non_compliant: count("non_compliant"), unknown: count("unknown"), compliance_percent: devices.length ? Math.round((count("compliant") / devices.length) * 1000) / 10 : 100 },
        columns: ["hostname", "user", "platform", "os", "serial", "compliance", "failing_checks", "grace_until", "last_seen"],
        rows: devices.map((d) => [d.hostname, d.email ?? "", d.platform, `${d.os_name} ${d.os_version}`.trim(), d.serial, d.compliance, (byDevice.get(d.id) ?? []).sort().join(" "), iso(d.compliance_grace_until), iso(d.last_seen_at)]),
      };
    }
    case "app_access": {
      const rows = (
        await sql<{ app: string; email: string; given_name: string; family_name: string; via: string; status: string }>`
          SELECT a.name AS app, u.email, u.given_name, u.family_name, 'direct' AS via, u.status
          FROM app_assignments x JOIN applications a ON a.id = x.app_id JOIN users u ON u.id = x.principal_id
          WHERE x.principal_type = 'user'
          UNION ALL
          SELECT a.name, u.email, u.given_name, u.family_name, 'group ' || g.name, u.status
          FROM app_assignments x JOIN applications a ON a.id = x.app_id JOIN groups g ON g.id = x.principal_id
          JOIN group_members m ON m.group_id = g.id JOIN users u ON u.id = m.user_id
          WHERE x.principal_type = 'group'
          ORDER BY 1, 2, 5`.execute(tx)
      ).rows.filter((r) => r.status !== "deprovisioned");
      return {
        summary: { apps: new Set(rows.map((r) => r.app)).size, grants: rows.length, people: new Set(rows.map((r) => r.email)).size },
        columns: ["app", "name", "email", "via", "status"],
        rows: rows.map((r) => [r.app, name(r), r.email, r.via, r.status]),
      };
    }
    case "agent_tool_access": {
      const agents = await tx.selectFrom("ai_agents").select(["id", "name", "tags", "status", "risk_tier", "last_seen_at"]).orderBy("name").execute();
      const servers = await tx.selectFrom("mcp_servers").select(["id", "name", "status"]).orderBy("name").execute();
      const tools = await tx.selectFrom("mcp_tools").selectAll().where("status", "<>", "removed").orderBy("name").execute();
      const perms = (await tx.selectFrom("mcp_permissions").selectAll().execute()).map((r) => ({ ...r, conditions: r.conditions as unknown as Condition[] }));
      const rows: Cell[][] = [];
      for (const a of agents) {
        for (const s of servers) {
          const rules: Rule[] = perms.filter((p) => p.server_id === s.id);
          for (const t of tools.filter((x) => x.server_id === s.id)) {
            const d = authorize(t as Tool, rules, { agentId: a.id, tags: a.tags }, null);
            if (!d.allow) continue;
            const conditional = rules.some((r) => r.id === d.rule_id && r.conditions.length > 0);
            rows.push([a.name, a.status, a.risk_tier, s.name, s.status, t.name, t.risk, conditional ? "with argument conditions" : "yes", iso(a.last_seen_at)]);
          }
        }
      }
      return {
        summary: { agents: agents.length, servers: servers.length, grants: rows.length, destructive_grants: rows.filter((r) => r[6] === "destructive").length },
        columns: ["agent", "agent_status", "agent_risk_tier", "server", "server_status", "tool", "tool_risk", "allowed", "agent_last_seen"],
        rows,
      };
    }
  }
}

const ReportOut = z
  .object({
    kind: z.enum(KINDS),
    title: z.string(),
    description: z.string(),
    generated_at: z.string(),
    summary: z.record(z.string(), z.union([z.number(), z.string()])),
    columns: z.array(z.string()),
    rows: z.array(z.array(z.union([z.string(), z.number(), z.boolean(), z.null()]))),
  })
  .openapi("Report");

export function registerReportRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/reports",
      tags: ["Reports"],
      summary: "List available reports",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(z.object({ kind: z.enum(KINDS), title: z.string(), description: z.string() })) })), ...problemResponses },
    }),
    async (c) => {
      requirePermission(c, "audit:read");
      return c.json({ data: KINDS.map((k) => ({ kind: k, title: TITLES[k][0], description: TITLES[k][1] })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/reports/{kind}",
      tags: ["Reports"],
      summary: "Generate a report",
      description: "JSON by default; `format=csv` downloads it (formula-safe for spreadsheets). Generating a report is audited.",
      security: bearer,
      request: { params: z.object({ kind: z.enum(KINDS) }), query: z.object({ format: z.enum(["json", "csv"]).default("json"), days: z.coerce.number().int().min(7).max(730).default(90).openapi({ description: "dormant_accounts: no sign-in for this many days" }) }) },
      responses: { 200: { description: "The report", content: { "application/json": { schema: ReportOut }, "text/csv": { schema: z.string() } } }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "audit:read");
      const { kind } = c.req.valid("param");
      const { format, days } = c.req.valid("query");
      const r = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const body = await build(tx, kind, days);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "report.generated", details: { report: kind, format, rows: body.rows.length } });
        return body;
      });
      const generated_at = new Date().toISOString();
      if (format === "csv") return c.body(toCsv(r.columns, r.rows), 200, { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="${kind}-${generated_at.slice(0, 10)}.csv"` });
      return c.json({ kind, title: TITLES[kind][0], description: TITLES[kind][1], generated_at, ...r }, 200);
    },
  );
}

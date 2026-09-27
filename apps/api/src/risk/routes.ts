import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { notFound } from "../platform/errors.js";
import { enqueue, type JobRunner, registerJobHandler } from "../platform/jobs.js";
import { bearer, Id, json, problemResponses } from "../schemas.js";
import { computeRisk, graphFor, type Level } from "./engine.js";

const LevelEnum = z.enum(["low", "medium", "high", "critical"]);
const FactorOut = z.object({ key: z.string(), points: z.number().int(), title: z.string(), detail: z.string(), device: z.object({ id: z.string(), hostname: z.string() }).optional() });
const PersonRiskOut = z
  .object({
    user_id: Id,
    email: z.string(),
    name: z.string(),
    score: z.number().int().openapi({ description: "0–100: the sum of the factors' points" }),
    level: LevelEnum,
    factors: z.array(FactorOut),
    devices: z.number().int(),
    ai_clients: z.number().int(),
    mcp_servers: z.number().int(),
    agents: z.number().int(),
  })
  .openapi("PersonRisk");
const NodeOut = z.object({
  id: z.string(),
  type: z.enum(["person", "device", "client", "server", "gateway_server", "tools", "agent"]),
  column: z.number().int(),
  label: z.string(),
  sublabel: z.string(),
  tone: z.enum(["neutral", "success", "warning", "danger"]),
  href: z.string().optional(),
});
const EdgeOut = z.object({ from: z.string(), to: z.string(), label: z.string(), tone: z.enum(["neutral", "success", "warning", "danger"]), dashed: z.boolean().optional() });

const RANK: Record<Level, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const SYSTEM: RequestMeta = { ip: "", userAgent: "nexus-risk", requestId: "" };

/** Stores everyone's risk and records who crossed into high or critical (the first run is a baseline). */
export async function recomputeRisk(tx: Tx, orgId: string) {
  const people = await computeRisk(tx);
  const before = new Map((await tx.selectFrom("risk_scores").select(["user_id", "level", "score"]).execute()).map((r) => [r.user_id, r]));
  const baseline = before.size === 0;
  const raised: string[] = [];
  for (const p of people) {
    const prev = before.get(p.user_id);
    await tx
      .insertInto("risk_scores")
      .values({ org_id: orgId, user_id: p.user_id, score: p.score, level: p.level, factors: JSON.stringify(p.factors), computed_at: new Date() })
      .onConflict((oc) => oc.column("user_id").doUpdateSet({ score: p.score, level: p.level, factors: JSON.stringify(p.factors), computed_at: new Date() }))
      .execute();
    if (!baseline && RANK[p.level] >= RANK.high && RANK[p.level] > RANK[prev?.level ?? "low"]) {
      raised.push(p.user_id);
      await audit(tx, orgId, { meta: SYSTEM }, {
        type: "user.risk_raised",
        actor: { type: "system", id: null, display: "Risk engine" },
        target: { type: "user", id: p.user_id, display: p.email },
        details: { from: prev?.level ?? "low", to: p.level, score: p.score, factors: p.factors.map((f) => `${f.title} (+${f.points})`) },
      });
    }
  }
  const gone = [...before.keys()].filter((id) => !people.some((p) => p.user_id === id));
  if (gone.length) await tx.deleteFrom("risk_scores").where("user_id", "in", gone).execute();
  return { people: people.length, raised };
}

registerJobHandler("risk.recompute", async (deps, job) => {
  await deps.db.tenant(job.org_id, (tx) => recomputeRisk(tx, job.org_id));
});

/** Hourly: the graph changes with every check-in, sync and policy edit; an hour is soon enough to alert. */
export function scheduleRisk(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 60 * 60_000) return;
    last = Date.now();
    const orgs = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_orgs_for_risk()`.execute(tx)).rows);
    for (const o of orgs) await deps.db.tenant(o.org_id, (tx) => enqueue(tx, o.org_id, "risk.recompute", {}, { dedupeKey: "risk.recompute" }));
  });
}

export function registerRiskRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/risk/people",
      tags: ["Risk"],
      summary: "People by risk, with the reasons",
      description: "Scores from each person's admin rights, MFA, devices, the AI clients and MCP servers on them, and the AI agents they own. Every point comes from a named factor.",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(PersonRiskOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      requirePermission(c, "devices:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => computeRisk(tx)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/risk/people/{id}/graph",
      tags: ["Risk"],
      summary: "A person's access graph: devices, AI clients, MCP servers, gateway tools and owned AI agents",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ person: PersonRiskOut, nodes: z.array(NodeOut), edges: z.array(EdgeOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      requirePermission(c, "devices:read");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const person = (await computeRisk(tx)).find((x) => x.user_id === id);
        const graph = await graphFor(tx, id);
        if (!person || !graph) throw notFound("Person");
        return { person, ...graph };
      });
      return c.json(out, 200);
    },
  );
}

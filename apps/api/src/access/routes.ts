import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { Conditions, evaluate, REQUIREMENTS } from "./engine.js";
import { groupsOf, loadDevice, loadPolicies } from "./service.js";

const PolicyInput = z.object({
  name: z.string().trim().min(1).max(100),
  enabled: z.boolean().default(true),
  mode: z.enum(["report_only", "enforce"]).default("report_only").openapi({ description: "Start in report-only to see the impact first" }),
  requirement: z.enum(REQUIREMENTS),
  conditions: Conditions,
});

const PolicyOut = PolicyInput.extend({
  id: Id,
  impact_7d: z.object({ would_block: z.number().int(), blocked: z.number().int() }),
  created_at: z.string(),
  updated_at: z.string(),
}).openapi("AccessPolicy");

const PolicyResult = z
  .object({
    policy_id: Id,
    name: z.string(),
    mode: z.enum(["report_only", "enforce"]),
    requirement: z.enum(REQUIREMENTS),
    matched: z.boolean(),
    satisfied: z.boolean().nullable(),
    reason: z.string(),
  })
  .openapi("PolicyResult");

const Simulation = z
  .object({ outcome: z.enum(["allow", "block", "needs_device", "needs_mfa"]), reason: z.string(), results: z.array(PolicyResult) })
  .openapi("AccessSimulation");

async function listOut(tx: Tx) {
  const rows = await tx.selectFrom("access_policies").selectAll().orderBy("created_at").execute();
  const impact = await sql<{ policy_id: string; would_block: number }>`
    SELECT details->>'policy_id' AS policy_id, count(*)::int AS would_block
    FROM audit_events WHERE type = 'access.would_block' AND ts > now() - interval '7 days'
    GROUP BY 1`.execute(tx);
  const blocked = await sql<{ policy_id: string; n: number }>`
    SELECT p->>'policy_id' AS policy_id, count(*)::int AS n
    FROM audit_events, jsonb_array_elements(details->'policies') p
    WHERE type = 'sso.login' AND outcome = 'denied' AND details->>'reason' = 'access_policy'
      AND p->>'mode' = 'enforce' AND (p->>'satisfied')::boolean = false AND ts > now() - interval '7 days'
    GROUP BY 1`.execute(tx);
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    enabled: r.enabled,
    mode: r.mode,
    requirement: r.requirement,
    conditions: Conditions.parse(r.conditions),
    impact_7d: {
      would_block: impact.rows.find((i) => i.policy_id === r.id)?.would_block ?? 0,
      blocked: blocked.rows.find((b) => b.policy_id === r.id)?.n ?? 0,
    },
    created_at: iso(r.created_at),
    updated_at: iso(r.updated_at),
  }));
}

export function registerAccessPolicyRoutes(app: App) {
  const listResponse = { 200: json(z.object({ data: z.array(PolicyOut) })), ...problemResponses };

  app.openapi(
    createRoute({ method: "get", path: "/v1/access-policies", tags: ["Conditional access"], summary: "Conditional access policies, with their 7-day impact", security: bearer, responses: listResponse }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, listOut) }, 200);
    },
  );

  const write = async (c: Parameters<Parameters<typeof app.openapi>[1]>[0], fn: (tx: Tx, p: ReturnType<typeof requirePermission>) => Promise<void>) => {
    const p = requirePermission(c, "policies:write");
    try {
      return await c.get("deps").db.tenant(p.orgId, async (tx) => {
        // Access policies can lock people out of apps: changing them needs fresh MFA.
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        await fn(tx, p);
        return listOut(tx);
      });
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict("name_taken", "A policy with this name already exists");
      throw err;
    }
  };

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/access-policies",
      tags: ["Conditional access"],
      summary: "Create a policy (requires recent MFA)",
      security: bearer,
      request: body(PolicyInput),
      responses: { 201: json(z.object({ data: z.array(PolicyOut) }), "Created"), ...problemResponses },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const data = await write(c, async (tx, p) => {
        const id = newId();
        await tx.insertInto("access_policies").values({ id, org_id: p.orgId, ...input, conditions: JSON.stringify(input.conditions), updated_at: new Date() }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "access.policy_created", target: { type: "access_policy", id, display: input.name }, details: input });
      });
      return c.json({ data }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/access-policies/{id}",
      tags: ["Conditional access"],
      summary: "Replace a policy (requires recent MFA)",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(PolicyInput) },
      responses: listResponse,
    }),
    async (c) => {
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const data = await write(c, async (tx, p) => {
        const before = await tx.selectFrom("access_policies").selectAll().where("id", "=", id).executeTakeFirst();
        if (!before) throw notFound("Policy");
        await tx.updateTable("access_policies").set({ ...input, conditions: JSON.stringify(input.conditions), updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: before.mode !== input.mode && input.mode === "enforce" ? "access.policy_enforced" : "access.policy_updated",
          target: { type: "access_policy", id, display: input.name },
          details: { from: { mode: before.mode, enabled: before.enabled, requirement: before.requirement, conditions: before.conditions }, to: input },
        });
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/access-policies/{id}", tags: ["Conditional access"], summary: "Delete a policy (requires recent MFA)", security: bearer, request: { params: z.object({ id: Id }) }, responses: listResponse }),
    async (c) => {
      const { id } = c.req.valid("param");
      const data = await write(c, async (tx, p) => {
        const r = await tx.deleteFrom("access_policies").where("id", "=", id).returning("name").executeTakeFirst();
        if (!r) throw notFound("Policy");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "access.policy_deleted", target: { type: "access_policy", id, display: r.name } });
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/access-policies/simulate",
      tags: ["Conditional access"],
      summary: "What-if: how would a sign-in be decided? (SPEC CA-03)",
      description: "Evaluates every policy, including report-only ones, as if they were enforced, and explains each result.",
      security: bearer,
      request: body(z.object({ user_id: Id, app_id: Id, mfa: z.boolean(), device_id: Id.nullable() })),
      responses: { 200: json(Simulation), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        if (!(await tx.selectFrom("users").select("id").where("id", "=", input.user_id).executeTakeFirst())) throw notFound("User");
        if (!(await tx.selectFrom("applications").select("id").where("id", "=", input.app_id).executeTakeFirst())) throw notFound("Application");
        const device = await loadDevice(tx, input.device_id);
        if (input.device_id && !device) throw notFound("Device");
        // Treat report-only policies as enforced so admins see what enforcing would do.
        const policies = (await loadPolicies(tx)).map((x) => ({ ...x, mode: "enforce" as const }));
        const real = new Map((await loadPolicies(tx)).map((x) => [x.id, x.mode]));
        const d = evaluate(policies, { userId: input.user_id, groupIds: await groupsOf(tx, input.user_id), appId: input.app_id, mfa: input.mfa, device });
        return { ...d, results: d.results.map((r) => ({ ...r, mode: real.get(r.policy_id)! })) };
      });
      return c.json(out, 200);
    },
  );
}

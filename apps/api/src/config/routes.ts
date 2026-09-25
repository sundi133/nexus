import { createRoute, z } from "@hono/zod-openapi";
import type { App, Env } from "../context.js";
import type { Context } from "hono";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { badRequest, conflict } from "../platform/errors.js";
import { bearer, body, json, problemResponses } from "../schemas.js";
import { ConfigDoc, ConfigError, exportConfig, reconcile, SECTION_PERMISSION } from "./engine.js";

/** Config as code: export, plan and apply an organization's policies (SPEC OPS-07). */

const ChangeOut = z
  .object({ section: z.string(), action: z.enum(["create", "update", "delete"]), key: z.string(), changes: z.record(z.string(), z.object({ from: z.unknown(), to: z.unknown() })).optional() })
  .openapi("ConfigChange");
const PlanOut = z.object({ plan_id: z.string().openapi({ description: "Pass to apply to make sure nothing changed since the plan" }), changes: z.array(ChangeOut) }).openapi("ConfigPlan");
const Request = z.object({ config: ConfigDoc, prune: z.boolean().default(false).openapi({ description: "Also delete what a listed section doesn't mention" }) });

/** Changing a section needs that section's permission (an unchanged section needs none). */
function requireChanged(c: Context<Env>, changes: { section: string }[]) {
  for (const section of new Set(changes.map((x) => x.section))) requirePermission(c, SECTION_PERMISSION[section as keyof typeof SECTION_PERMISSION]);
}

const asProblem = (e: unknown) => {
  if (e instanceof ConfigError) return badRequest("invalid_config", `The config can't be applied: ${e.problems.length} problem${e.problems.length === 1 ? "" : "s"}`, { problems: e.problems });
  return e;
};

export function registerConfigRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/config",
      tags: ["Config as code"],
      summary: "Export the organization's config",
      description: "Settings, groups (not directory-managed), conditional access, device policies, alert rules, agents and MCP servers with their permissions, by name. Secrets are never included; MCP server auth names an environment variable for the CLI instead.",
      security: bearer,
      responses: { 200: json(ConfigDoc), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const doc = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const d = await exportConfig(tx, p.orgId);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "config.exported" });
        return d;
      });
      return c.json(doc, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/config/plan", tags: ["Config as code"], summary: "Plan a config change", description: "What apply would change. Nothing is changed.", security: bearer, request: body(Request), responses: { 200: json(PlanOut), ...problemResponses } }),
    async (c) => {
      const input = c.req.valid("json");
      const p = requirePermission(c, "org:manage");
      try {
        const out = await c.get("deps").db.tenant(p.orgId, (tx) => reconcile(tx, c.get("deps"), p, c.get("meta"), input.config, { apply: false, prune: input.prune }));
        requireChanged(c, out.changes);
        return c.json(out, 200);
      } catch (e) {
        throw asProblem(e);
      }
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/config/apply",
      tags: ["Config as code"],
      summary: "Apply a config",
      description: "Makes the organization match the document, all or nothing, and records every change in the audit log. With `plan_id`, refuses if the plan would now be different.",
      security: bearer,
      request: body(Request.extend({ plan_id: z.string().max(64).optional() })),
      responses: { 200: json(PlanOut), ...problemResponses },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      try {
        const out = await deps.db.tenant(p.orgId, async (tx) => {
          requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
          const r = await reconcile(tx, deps, p, c.get("meta"), input.config, { apply: true, prune: input.prune });
          requireChanged(c, r.changes); // inside the transaction: refusing rolls everything back
          if (input.plan_id && input.plan_id !== r.plan_id) throw conflict("plan_changed", "Something changed since the plan. Plan again and review.");
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "config.applied", details: { plan_id: r.plan_id, changes: r.changes.length, prune: input.prune, sections: Object.keys(input.config).filter((k) => k !== "version") } });
          return r;
        });
        return c.json(out, 200);
      } catch (e) {
        throw asProblem(e);
      }
    },
  );
}

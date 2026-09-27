import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { assertUserInScope, requirePermission, requireRecentMfa, requireSession } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { notFound } from "../platform/errors.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { ArgAction, DEFAULT_MCP_DLP, DETECTOR_IDS, loadMcpDlp, ResultAction } from "./dlp.js";

/**
 * People and the MCP gateway: the data-protection policy for tool calls, and the AI clients
 * each person has connected (which they, or an admin, can disconnect).
 */

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
    .refine((p) => !/\([^)]*[+*][^)]*\)[+*{]/.test(p), "Nested repetition (like (a+)+) is too slow to run on every tool call"),
  arguments: ArgAction.default("off"),
  results: ResultAction.default("off"),
});

const DlpIn = z
  .object({
    arguments: z.partialRecord(z.enum(DETECTOR_IDS), ArgAction).default({}).openapi({ description: "What tool arguments may carry: off, monitor, or block the call" }),
    results: z.partialRecord(z.enum(DETECTOR_IDS), ResultAction).default({}).openapi({ description: "What the AI may read in results: off, monitor, or redact first" }),
    custom: z.array(CustomPattern).max(50).default([]),
  })
  .openapi("McpDataProtectionInput");

const DlpOut = z
  .object({ arguments: z.record(z.string(), ArgAction), results: z.record(z.string(), ResultAction), custom: z.array(CustomPattern), defaults: z.object({ arguments: z.record(z.string(), ArgAction), results: z.record(z.string(), ResultAction) }) })
  .openapi("McpDataProtection");

const Connection = z
  .object({ id: Id, client: z.string(), resource: z.string(), created_at: z.string(), last_used_at: z.string(), expires_at: z.string() })
  .openapi("McpConnection");

async function connectionsOf(tx: Tx, userId: string) {
  const rows = await tx
    .selectFrom("mcp_grants")
    .innerJoin("mcp_clients", "mcp_clients.id", "mcp_grants.client_id")
    .select(["mcp_grants.id", "mcp_clients.name", "mcp_grants.resource", "mcp_grants.created_at", "mcp_grants.last_used_at", "mcp_grants.expires_at"])
    .where("mcp_grants.user_id", "=", userId)
    .where("mcp_grants.revoked_at", "is", null)
    .where("mcp_grants.expires_at", ">", new Date())
    .orderBy("mcp_grants.last_used_at", "desc")
    .execute();
  return rows.map((r) => ({ id: r.id, client: r.name, resource: r.resource, created_at: iso(r.created_at), last_used_at: iso(r.last_used_at), expires_at: iso(r.expires_at) }));
}

export function registerMcpPeopleRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/mcp/data-protection", tags: ["MCP gateway"], summary: "What tool calls may carry, and what AI may read", security: bearer, responses: { 200: json(DlpOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "agents:read");
      const d = await c.get("deps").db.tenant(p.orgId, loadMcpDlp);
      return c.json({ ...d, defaults: { arguments: DEFAULT_MCP_DLP.arguments, results: DEFAULT_MCP_DLP.results } } as z.infer<typeof DlpOut>, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/mcp/data-protection",
      tags: ["MCP gateway"],
      summary: "Set data protection for tool calls",
      description: "Applies to every MCP server behind the gateway, for agents and people alike. Needs `mcp:manage` and a recent MFA.",
      security: bearer,
      request: body(DlpIn),
      responses: { 200: json(DlpOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const before = await loadMcpDlp(tx);
        const row = { arguments: JSON.stringify(input.arguments), results: JSON.stringify(input.results), custom: JSON.stringify(input.custom), updated_at: new Date(), updated_by: p.userId };
        await tx.insertInto("mcp_dlp_policies").values({ org_id: p.orgId, ...row }).onConflict((oc) => oc.column("org_id").doUpdateSet(row)).execute();
        const after = await loadMcpDlp(tx);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.data_protection_updated", details: { from: before, to: after } });
        return after;
      });
      return c.json({ ...out, defaults: { arguments: DEFAULT_MCP_DLP.arguments, results: DEFAULT_MCP_DLP.results } } as z.infer<typeof DlpOut>, 200);
    },
  );

  // ---- A person's AI clients --------------------------------------------------------------------

  app.openapi(
    createRoute({ method: "get", path: "/v1/me/mcp-connections", tags: ["MCP gateway"], summary: "AI clients I've connected to MCP servers through Nexus", security: bearer, responses: { 200: json(z.object({ data: z.array(Connection) })), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => connectionsOf(tx, p.userId)) }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/me/mcp-connections/{id}", tags: ["MCP gateway"], summary: "Disconnect one of my AI clients", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Disconnected" }, ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const g = await tx.updateTable("mcp_grants").set({ revoked_at: new Date() }).where("id", "=", id).where("user_id", "=", p.userId).where("revoked_at", "is", null).returning("id").executeTakeFirst();
        if (!g) throw notFound("Connection");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.grant_revoked", target: { type: "user", id: p.userId, display: p.email }, details: { grant_id: id, by: "self" } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/users/{id}/mcp-connections", tags: ["MCP gateway"], summary: "A person's AI clients connected through the gateway", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(z.object({ data: z.array(Connection) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "users:read", { scoped: true });
      const { id } = c.req.valid("param");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertUserInScope(tx, p, "users:read", id);
        return connectionsOf(tx, id);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/users/{id}/mcp-connections/{grantId}", tags: ["MCP gateway"], summary: "Disconnect one of a person's AI clients", security: bearer, request: { params: z.object({ id: Id, grantId: Id }) }, responses: { 204: { description: "Disconnected" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "users:lifecycle", { scoped: true });
      const { id, grantId } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertUserInScope(tx, p, "users:lifecycle", id);
        const g = await tx.updateTable("mcp_grants").set({ revoked_at: new Date() }).where("id", "=", grantId).where("user_id", "=", id).where("revoked_at", "is", null).returning("id").executeTakeFirst();
        if (!g) throw notFound("Connection");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.grant_revoked", target: { type: "user", id, display: "" }, details: { grant_id: grantId, by: "admin" } });
      });
      return c.body(null, 204);
    },
  );
}

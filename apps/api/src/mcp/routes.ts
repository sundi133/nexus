import { createRoute, z } from "@hono/zod-openapi";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { gatewayBase } from "../ai-agents/tokens.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { assertSafeUrl, UnsafeUrlError } from "../platform/outbound.js";
import { bearer, body, Id, iso, json, patchOf, problemResponses, Timestamp } from "../schemas.js";
import { authorize, type Condition as PolicyCondition, isUsable, RISKS, type Rule, type Tool as PolicyTool } from "./policy.js";
import { serverAad, syncServer } from "./service.js";
import { forgetSession } from "./upstream.js";

/** Admin API for the MCP gateway: servers, tool approval and risk, permissions, what-if. */

const Risk = z.enum(RISKS);

const Auth = z
  .discriminatedUnion("kind", [
    z.object({ kind: z.literal("none") }),
    z.object({ kind: z.literal("bearer"), token: z.string().min(1).max(4000) }),
    z.object({ kind: z.literal("header"), header: z.string().regex(/^[A-Za-z0-9-]{1,64}$/), value: z.string().min(1).max(4000) }),
  ])
  .openapi("McpServerAuth", { description: "How the gateway authenticates to the upstream. Stored sealed; never returned or shown to agents." });

const ServerInput = z.object({
  name: z.string().trim().min(1).max(100),
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,39}$/, "Lowercase letters, digits and dashes").openapi({ example: "github" }),
  description: z.string().trim().max(1000).default(""),
  url: z.string().url().max(500).openapi({ example: "https://api.githubcopilot.com/mcp/" }),
  auth: Auth.default({ kind: "none" }),
  auto_approve_read: z.boolean().default(false).openapi({ description: "Approve newly discovered read-only tools automatically" }),
  calls_per_minute: z.number().int().min(1).max(10000).default(120).openapi({ description: "Per agent" }),
  status: z.enum(["active", "disabled"]).default("active"),
});

const ToolOut = z
  .object({
    id: Id,
    name: z.string(),
    title: z.string(),
    description: z.string(),
    input_schema: z.record(z.string(), z.unknown()),
    annotations: z.record(z.string(), z.unknown()),
    status: z.enum(["pending", "approved", "blocked", "removed"]),
    usable: z.boolean().openapi({ description: "Approved as it is now" }),
    change: z.enum(["new", "changed", ""]),
    approved: z.object({ title: z.string(), description: z.string(), input_schema: z.unknown(), annotations: z.unknown() }).nullable().openapi({ description: "What was approved, when the tool has changed since" }),
    risk: Risk,
    risk_source: z.enum(["heuristic", "annotations", "admin"]),
    first_seen_at: Timestamp,
    changed_at: Timestamp,
    approved_at: Timestamp.nullable(),
  })
  .openapi("McpTool");

const ConditionSchema = z
  .object({
    argument: z.string().trim().min(1).max(100).openapi({ description: "Argument name; dotted for nested (e.g. repo.owner)" }),
    op: z.enum(["equals", "in", "not_in", "prefix"]),
    values: z.array(z.string().max(300)).min(1).max(100),
  })
  .openapi("McpCondition");

const PermissionInput = z.object({
  effect: z.enum(["allow", "deny"]),
  subject: z.discriminatedUnion("type", [z.object({ type: z.literal("all_agents") }), z.object({ type: z.literal("agent"), id: Id }), z.object({ type: z.literal("agent_tag"), tag: z.string().trim().min(1).max(50) })]),
  tools: z.array(z.string().min(1).max(128)).min(1).max(200).openapi({ description: 'Tool names, or ["*"] for every approved tool' }),
  risks: z.array(Risk).min(1).nullable().default(null).openapi({ description: "Only tools of these risk classes; null for any" }),
  conditions: z.array(ConditionSchema).max(10).default([]),
  description: z.string().trim().max(500).default(""),
});

const PermissionOut = z
  .object({
    id: Id,
    effect: z.enum(["allow", "deny"]),
    subject: z.object({ type: z.enum(["all_agents", "agent", "agent_tag"]), id: Id.nullable(), tag: z.string().nullable(), name: z.string() }),
    tools: z.array(z.string()),
    risks: z.array(Risk).nullable(),
    conditions: z.array(ConditionSchema),
    description: z.string(),
    created_at: Timestamp,
  })
  .openapi("McpPermission");

const ServerOut = z
  .object({
    id: Id,
    name: z.string(),
    slug: z.string(),
    description: z.string(),
    url: z.string(),
    auth: z.object({ kind: z.enum(["none", "bearer", "header"]), header: z.string() }),
    status: z.enum(["active", "disabled"]),
    auto_approve_read: z.boolean(),
    calls_per_minute: z.number().int(),
    endpoint: z.string().openapi({ description: "Where agents connect (streamable HTTP)" }),
    server_info: z.record(z.string(), z.unknown()),
    tools: z.object({ total: z.number().int(), usable: z.number().int(), pending: z.number().int() }),
    last_synced_at: Timestamp.nullable(),
    last_sync_error: z.string(),
    created_at: Timestamp,
  })
  .openapi("McpServer");

type ServerRow = { id: string; name: string; slug: string; description: string; url: string; auth_kind: "none" | "bearer" | "header"; auth_header: string; status: "active" | "disabled"; auto_approve_read: boolean; calls_per_minute: number; server_info: unknown; last_synced_at: Date | null; last_sync_error: string; created_at: Date };
type ToolRow = Awaited<ReturnType<typeof toolsOf>>[number];

const toolsOf = (tx: Tx, serverId: string) => tx.selectFrom("mcp_tools").selectAll().where("server_id", "=", serverId).orderBy("name").execute();

const toServer = (deps: Deps, orgSlug: string, s: ServerRow, tools: ToolRow[]): z.infer<typeof ServerOut> => ({
  id: s.id,
  name: s.name,
  slug: s.slug,
  description: s.description,
  url: s.url,
  auth: { kind: s.auth_kind, header: s.auth_header },
  status: s.status,
  auto_approve_read: s.auto_approve_read,
  calls_per_minute: s.calls_per_minute,
  endpoint: `${gatewayBase(deps, orgSlug)}/${s.slug}`,
  server_info: (s.server_info ?? {}) as Record<string, unknown>,
  tools: {
    total: tools.filter((t) => t.status !== "removed").length,
    usable: tools.filter((t) => isUsable(t as PolicyTool)).length,
    pending: tools.filter((t) => t.status === "pending").length,
  },
  last_synced_at: s.last_synced_at ? iso(s.last_synced_at) : null,
  last_sync_error: s.last_sync_error,
  created_at: iso(s.created_at),
});

const toTool = (t: ToolRow): z.infer<typeof ToolOut> => ({
  id: t.id,
  name: t.name,
  title: t.title,
  description: t.description,
  input_schema: t.input_schema as Record<string, unknown>,
  annotations: t.annotations as Record<string, unknown>,
  status: t.status,
  usable: isUsable(t as PolicyTool),
  change: t.change,
  approved: t.approved_hash && t.approved_hash !== t.hash ? (t.approved_snapshot as z.infer<typeof ToolOut>["approved"]) : null,
  risk: t.risk,
  risk_source: t.risk_source,
  first_seen_at: iso(t.first_seen_at),
  changed_at: iso(t.changed_at),
  approved_at: t.approved_at ? iso(t.approved_at) : null,
});

async function permissionsOf(tx: Tx, serverId: string): Promise<z.infer<typeof PermissionOut>[]> {
  const rows = await tx
    .selectFrom("mcp_permissions")
    .leftJoin("ai_agents", "ai_agents.id", "mcp_permissions.subject_id")
    .selectAll("mcp_permissions")
    .select("ai_agents.name as agent_name")
    .where("server_id", "=", serverId)
    .orderBy("effect", "desc") // deny first
    .orderBy("created_at")
    .execute();
  return rows.map((r) => ({
    id: r.id,
    effect: r.effect,
    subject: { type: r.subject_type, id: r.subject_id, tag: r.subject_tag, name: r.subject_type === "all_agents" ? "All agents" : r.subject_type === "agent_tag" ? `Agents tagged ${r.subject_tag}` : (r.agent_name ?? "Deleted agent") },
    tools: r.tools,
    risks: r.risks as z.infer<typeof Risk>[] | null,
    conditions: r.conditions as unknown as z.infer<typeof ConditionSchema>[],
    description: r.description,
    created_at: iso(r.created_at),
  }));
}

async function getServer(tx: Tx, id: string) {
  const s = await tx.selectFrom("mcp_servers").selectAll().where("id", "=", id).executeTakeFirst();
  if (!s) throw notFound("MCP server");
  return s;
}

const orgSlug = async (tx: Tx, orgId: string) => (await tx.selectFrom("organizations").select("slug").where("id", "=", orgId).executeTakeFirstOrThrow()).slug;

export function registerMcpRoutes(app: App) {
  const stepUp = async (c: Parameters<typeof requireRecentMfa>[0], tx: Tx, p: Parameters<typeof requireRecentMfa>[1]) => requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
  const checkUrl = async (deps: Deps, url: string) => {
    try {
      await assertSafeUrl(url, { allowPrivate: deps.cfg.allowPrivateOutbound });
    } catch (e) {
      throw badRequest("unsafe_url", e instanceof UnsafeUrlError ? e.message : "The URL can't be used");
    }
  };
  const sealAuth = (deps: Deps, id: string, auth: z.infer<typeof Auth>) =>
    auth.kind === "none"
      ? { auth_kind: "none" as const, auth_header: "", secret: null }
      : { auth_kind: auth.kind, auth_header: auth.kind === "header" ? auth.header : "", secret: deps.sealer.seal(Buffer.from(auth.kind === "bearer" ? auth.token : auth.value), serverAad(id)) };

  app.openapi(
    createRoute({ method: "get", path: "/v1/mcp/servers", tags: ["MCP gateway"], summary: "List MCP servers", security: bearer, responses: { 200: json(z.object({ data: z.array(ServerOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "agents:read");
      const deps = c.get("deps");
      const data = await deps.db.tenant(p.orgId, async (tx) => {
        const slug = await orgSlug(tx, p.orgId);
        const servers = await tx.selectFrom("mcp_servers").selectAll().orderBy("name").execute();
        const tools = await tx.selectFrom("mcp_tools").selectAll().execute();
        return servers.map((s) => toServer(deps, slug, s, tools.filter((t) => t.server_id === s.id)));
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/mcp/servers",
      tags: ["MCP gateway"],
      summary: "Register an MCP server",
      description: "The gateway connects at once to discover its tools. New tools need approval before agents can use them.",
      security: bearer,
      request: body(ServerInput),
      responses: { 201: json(z.object({ server: ServerOut, tools: z.array(ToolOut) }), "Registered"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      await checkUrl(deps, input.url);
      const id = newId();
      try {
        await deps.db.tenant(p.orgId, async (tx) => {
          await stepUp(c, tx, p);
          const { auth, ...rest } = input;
          await tx.insertInto("mcp_servers").values({ id, org_id: p.orgId, ...rest, ...sealAuth(deps, id, auth), created_by: p.apiKey ? null : p.userId, updated_at: new Date() }).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.server_registered", target: { type: "mcp_server", id, display: input.name }, details: { url: input.url, slug: input.slug, auth: input.auth.kind } });
        });
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("taken", "A server with this name or slug already exists");
        throw err;
      }
      await syncServer(deps, p.orgId, id, c.get("meta"));
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const tools = await toolsOf(tx, id);
        return { server: toServer(deps, await orgSlug(tx, p.orgId), await getServer(tx, id), tools), tools: tools.map(toTool) };
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/mcp/servers/{id}",
      tags: ["MCP gateway"],
      summary: "Get an MCP server with its tools and permissions",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ server: ServerOut, tools: z.array(ToolOut), permissions: z.array(PermissionOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:read");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const s = await getServer(tx, id);
        const tools = await toolsOf(tx, id);
        return { server: toServer(deps, await orgSlug(tx, p.orgId), s, tools), tools: tools.map(toTool), permissions: await permissionsOf(tx, id) };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/mcp/servers/{id}",
      tags: ["MCP gateway"],
      summary: "Update an MCP server",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(patchOf(ServerInput)) },
      responses: { 200: json(ServerOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const patch = c.req.valid("json");
      if (patch.url) await checkUrl(deps, patch.url);
      try {
        const out = await deps.db.tenant(p.orgId, async (tx) => {
          const before = await getServer(tx, id);
          if (patch.url || patch.auth) await stepUp(c, tx, p);
          const { auth, ...rest } = patch;
          await tx.updateTable("mcp_servers").set({ ...rest, ...(auth ? sealAuth(deps, id, auth) : {}), updated_at: new Date() }).where("id", "=", id).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.server_updated", target: { type: "mcp_server", id, display: before.name }, details: { changes: { ...rest, ...(auth ? { auth: auth.kind } : {}) } } });
          return toServer(deps, await orgSlug(tx, p.orgId), await getServer(tx, id), await toolsOf(tx, id));
        });
        forgetSession(id);
        return c.json(out, 200);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("taken", "A server with this name or slug already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/mcp/servers/{id}", tags: ["MCP gateway"], summary: "Remove an MCP server", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await getServer(tx, id);
        await tx.deleteFrom("mcp_servers").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.server_removed", target: { type: "mcp_server", id, display: s.name } });
      });
      forgetSession(id);
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/mcp/servers/{id}/sync",
      tags: ["MCP gateway"],
      summary: "Re-discover tools now",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ ok: z.boolean(), error: z.string(), added: z.array(z.string()), changed: z.array(z.string()), removed: z.array(z.string()), approved_automatically: z.array(z.string()) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, (tx) => getServer(tx, id));
      return c.json(await syncServer(c.get("deps"), p.orgId, id, c.get("meta")), 200);
    },
  );

  // ---- Tools ----

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/mcp/servers/{id}/tools/review",
      tags: ["MCP gateway"],
      summary: "Approve or block tools",
      description: "Approval covers the tool exactly as it is now (description, schema, annotations). If it changes, it needs approval again.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ names: z.array(z.string()).min(1).max(500), decision: z.enum(["approve", "block"]) })) },
      responses: { 200: json(z.object({ tools: z.array(ToolOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const { id } = c.req.valid("param");
      const { names, decision } = c.req.valid("json");
      const tools = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await getServer(tx, id);
        const rows = (await toolsOf(tx, id)).filter((t) => names.includes(t.name) && t.status !== "removed");
        if (rows.length !== new Set(names).size) throw notFound("One or more tools");
        const now = new Date();
        for (const t of rows) {
          await tx
            .updateTable("mcp_tools")
            .set(
              decision === "approve"
                ? { status: "approved", change: "", approved_hash: t.hash, approved_snapshot: JSON.stringify({ title: t.title, description: t.description, input_schema: t.input_schema, annotations: t.annotations }), approved_by: p.apiKey ? null : p.userId, approved_at: now }
                : { status: "blocked" },
            )
            .where("id", "=", t.id)
            .execute();
        }
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: decision === "approve" ? "mcp.tools_approved" : "mcp.tools_blocked",
          target: { type: "mcp_server", id, display: s.name },
          details: { tools: rows.map((t) => ({ name: t.name, risk: t.risk, hash: t.hash, previously_approved: t.approved_hash })) },
        });
        return (await toolsOf(tx, id)).map(toTool);
      });
      return c.json({ tools }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/mcp/servers/{id}/tools/{toolId}",
      tags: ["MCP gateway"],
      summary: "Set a tool's risk class",
      security: bearer,
      request: { params: z.object({ id: Id, toolId: Id }), ...body(z.object({ risk: Risk })) },
      responses: { 200: json(ToolOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const { id, toolId } = c.req.valid("param");
      const { risk } = c.req.valid("json");
      const t = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const before = await tx.selectFrom("mcp_tools").selectAll().where("id", "=", toolId).where("server_id", "=", id).executeTakeFirst();
        if (!before) throw notFound("Tool");
        await tx.updateTable("mcp_tools").set({ risk, risk_source: "admin" }).where("id", "=", toolId).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.tool_risk_set", target: { type: "mcp_tool", id: toolId, display: before.name }, details: { from: before.risk, to: risk } });
        return tx.selectFrom("mcp_tools").selectAll().where("id", "=", toolId).executeTakeFirstOrThrow();
      });
      return c.json(toTool(t), 200);
    },
  );

  // ---- Permissions ----

  const checkPermission = async (tx: Tx, serverId: string, input: z.infer<typeof PermissionInput>) => {
    if (input.subject.type === "agent" && !(await tx.selectFrom("ai_agents").select("id").where("id", "=", input.subject.id).executeTakeFirst())) throw notFound("Agent");
    if (input.tools.includes("*") && input.tools.length > 1) throw badRequest("invalid_tools", 'Use ["*"] alone, or list tools by name');
    if (!input.tools.includes("*")) {
      const known = new Set((await toolsOf(tx, serverId)).map((t) => t.name));
      const unknown = input.tools.filter((t) => !known.has(t));
      if (unknown.length) throw badRequest("unknown_tool", `Unknown tool: ${unknown.join(", ")}`);
    }
  };
  const permissionValues = (input: z.infer<typeof PermissionInput>) => ({
    effect: input.effect,
    subject_type: input.subject.type,
    subject_id: input.subject.type === "agent" ? input.subject.id : null,
    subject_tag: input.subject.type === "agent_tag" ? input.subject.tag.toLowerCase() : null,
    tools: input.tools,
    risks: input.risks,
    conditions: JSON.stringify(input.conditions),
    description: input.description,
  });

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/mcp/servers/{id}/permissions",
      tags: ["MCP gateway"],
      summary: "Add a tool permission",
      description: "Deny by default: agents can call a tool only when an allow rule matches (agent, tag or everyone; tool; risk; argument conditions) and no deny rule does.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(PermissionInput) },
      responses: { 201: json(z.object({ permissions: z.array(PermissionOut) }), "Added"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await getServer(tx, id);
        await checkPermission(tx, id, input);
        const pid = newId();
        await tx.insertInto("mcp_permissions").values({ id: pid, org_id: p.orgId, server_id: id, ...permissionValues(input), created_by: p.apiKey ? null : p.userId }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.permission_added", target: { type: "mcp_server", id, display: s.name }, details: { permission_id: pid, ...input } });
        return permissionsOf(tx, id);
      });
      return c.json({ permissions: out }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/mcp/servers/{id}/permissions/{permissionId}",
      tags: ["MCP gateway"],
      summary: "Replace a tool permission",
      security: bearer,
      request: { params: z.object({ id: Id, permissionId: Id }), ...body(PermissionInput) },
      responses: { 200: json(z.object({ permissions: z.array(PermissionOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const { id, permissionId } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await getServer(tx, id);
        await checkPermission(tx, id, input);
        const r = await tx.updateTable("mcp_permissions").set(permissionValues(input)).where("id", "=", permissionId).where("server_id", "=", id).executeTakeFirst();
        if (!Number(r.numUpdatedRows)) throw notFound("Permission");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.permission_changed", target: { type: "mcp_server", id, display: s.name }, details: { permission_id: permissionId, ...input } });
        return permissionsOf(tx, id);
      });
      return c.json({ permissions: out }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/mcp/servers/{id}/permissions/{permissionId}",
      tags: ["MCP gateway"],
      summary: "Remove a tool permission",
      security: bearer,
      request: { params: z.object({ id: Id, permissionId: Id }) },
      responses: { 204: { description: "Removed" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "mcp:manage");
      const { id, permissionId } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await getServer(tx, id);
        const r = await tx.deleteFrom("mcp_permissions").where("id", "=", permissionId).where("server_id", "=", id).executeTakeFirst();
        if (!Number(r.numDeletedRows)) throw notFound("Permission");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "mcp.permission_removed", target: { type: "mcp_server", id, display: s.name }, details: { permission_id: permissionId } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/mcp/servers/{id}/simulate",
      tags: ["MCP gateway"],
      summary: "What if an agent called this tool?",
      description: "Evaluates the current rules without calling anything.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ agent_id: Id, tool: z.string(), arguments: z.record(z.string(), z.unknown()).default({}) })) },
      responses: { 200: json(z.object({ allow: z.boolean(), reason: z.string(), rule_id: Id.nullable() }).openapi("McpDecision")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "agents:read");
      const { id } = c.req.valid("param");
      const q = c.req.valid("json");
      const d = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await getServer(tx, id);
        const agent = await tx.selectFrom("ai_agents").select(["id", "tags", "status"]).where("id", "=", q.agent_id).executeTakeFirst();
        if (!agent) throw notFound("Agent");
        const tool = (await toolsOf(tx, id)).find((t) => t.name === q.tool);
        const rules: Rule[] = (await tx.selectFrom("mcp_permissions").selectAll().where("server_id", "=", id).execute()).map((r) => ({ ...r, conditions: r.conditions as unknown as PolicyCondition[] }));
        if (agent.status !== "active") return { allow: false, reason: "The agent is suspended", rule_id: null };
        return authorize(tool as PolicyTool | undefined, rules, { agentId: agent.id, tags: agent.tags }, q.arguments);
      });
      return c.json(d, 200);
    },
  );
}

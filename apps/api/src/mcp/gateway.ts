import type { Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { sql } from "kysely";
import type { App, Deps, Env } from "../context.js";
import { audit } from "../audit/record.js";
import { RateLimiter } from "../auth/ratelimit.js";
import { createLocalJWKSet, jwtVerify } from "jose";
import { gatewayBase, verifyAgentToken, type AgentPrincipal } from "../ai-agents/tokens.js";
import { publicJwks } from "../sso/keys.js";
import { checkArguments, loadMcpDlp, type McpDlp, protectResult } from "./dlp.js";
import { type UserCaller, verifyUserToken } from "./oauth.js";
import type { Tx } from "../platform/db.js";
import { issuerFor } from "../sso/apps.js";
import { argsHash, authorize, type Condition, type Decision, type Rule, type Tool } from "./policy.js";
import { upstreamConfig, VERSION } from "./service.js";
import { request as upstreamRequest, UpstreamError } from "./upstream.js";

/**
 * The MCP gateway (SPEC MCP-01/03/04/07/08): one streamable-HTTP MCP endpoint
 * per upstream server, at {api}/mcp/{org}/{server}. It terminates the protocol
 * itself — initialize, ping, tools/list and tools/call — so nothing but
 * authorized tool calls reaches the upstream, with credentials the agent never
 * sees. Every call is decided (deny by default) and traced to the audit log.
 */

const SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_BODY = 1024 * 1024;

type Org = { org_id: string; name: string };
const orgBySlug = (deps: Deps, slug: string) => deps.db.unscoped(async (tx) => (await sql<Org>`SELECT * FROM nexus_org_by_slug(${slug})`.execute(tx)).rows[0]);

const serverUrl = (deps: Deps, slug: string, server: string) => `${gatewayBase(deps, slug)}/${server}`;
const metadataUrl = (deps: Deps, slug: string, server: string) => `${deps.cfg.apiPublicUrl}/.well-known/oauth-protected-resource/mcp/${slug}/${server}`;

// Per agent and server, per process (ARCHITECTURE §4: moves to a shared store with replicas).
const limiters = new Map<number, RateLimiter>();
const limiter = (perMinute: number) => {
  let l = limiters.get(perMinute);
  if (!l) limiters.set(perMinute, (l = new RateLimiter(perMinute, 60_000, `mcp-${perMinute}`)));
  return l;
};
const rateNoted = new Map<string, number>();

/** An AI agent with its own identity, or a person through their own MCP client. */
type GatewayCaller = ({ kind: "agent" } & AgentPrincipal) | UserCaller;
const callerKey = (who: GatewayCaller) => (who.kind === "user" ? `user:${who.userId}` : who.agentId);
const policyCaller = (who: GatewayCaller) => (who.kind === "user" ? { kind: "user" as const, userId: who.userId, groupIds: who.groupIds } : { kind: "agent" as const, agentId: who.agentId, tags: who.tags });
const auditActor = (who: GatewayCaller) =>
  who.kind === "user" ? { type: "user" as const, id: who.userId, display: who.email } : { type: "agent" as const, id: who.agentId, display: who.name };

type Rpc = { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> };
const rpcResult = (id: Rpc["id"], result: unknown) => ({ jsonrpc: "2.0", id, result });
const rpcError = (id: Rpc["id"], code: number, message: string, data?: unknown) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } });

function unauthorized(c: Context<Env>, deps: Deps, slug: string, server: string, description: string) {
  c.header("WWW-Authenticate", `Bearer resource_metadata="${metadataUrl(deps, slug, server)}", error="invalid_token", error_description="${description.replace(/"/g, "'")}"`);
  c.header("Cache-Control", "no-store");
  return c.json({ error: "invalid_token", error_description: description }, 401);
}

async function loadServer(tx: Tx, slug: string) {
  return tx.selectFrom("mcp_servers").selectAll().where("slug", "=", slug).executeTakeFirst();
}

async function rulesFor(tx: Tx, serverId: string): Promise<Rule[]> {
  const rows = await tx.selectFrom("mcp_permissions").selectAll().where("server_id", "=", serverId).execute();
  return rows.map((r) => ({ ...r, conditions: r.conditions as unknown as Condition[] }));
}

async function touchAgent(tx: Tx, agentId: string) {
  await sql`UPDATE ai_agents SET last_seen_at = now() WHERE id = ${agentId} AND (last_seen_at IS NULL OR last_seen_at < now() - interval '1 minute')`.execute(tx);
}

export function registerMcpGateway(app: App) {
  // RFC 9728 protected resource metadata: where MCP clients get tokens for this server.
  app.get("/.well-known/oauth-protected-resource/mcp/:slug/:server", async (c) => {
    const deps = c.get("deps");
    const { slug, server } = c.req.param();
    const org = await orgBySlug(deps, slug);
    if (!org) return c.json({ error: "not_found" }, 404);
    const s = await deps.db.tenant(org.org_id, (tx) => loadServer(tx, server));
    if (!s) return c.json({ error: "not_found" }, 404);
    c.header("Cache-Control", "public, max-age=300");
    return c.json({
      resource: serverUrl(deps, slug, server),
      authorization_servers: [issuerFor(deps, slug)],
      scopes_supported: ["mcp"],
      bearer_methods_supported: ["header"],
      resource_name: `${s.name} via Votal Nexus`,
    });
  });

  app.use("/mcp/*", bodyLimit({ maxSize: MAX_BODY, onError: (c) => c.json(rpcError(null, -32600, "The request is too large"), 413) }));

  app.on(["GET", "DELETE"], "/mcp/:slug/:server", (c) => {
    c.header("Allow", "POST");
    return c.json(rpcError(null, -32000, "This gateway answers POST requests only (no server-initiated stream)"), 405);
  });

  app.post("/mcp/:slug/:server", async (c) => {
    const deps = c.get("deps");
    const meta = c.get("meta");
    const { slug, server: serverSlug } = c.req.param();
    const header = c.req.header("authorization");
    if (!header?.startsWith("Bearer ")) return unauthorized(c, deps, slug, serverSlug, "An access token is required: sign in with your organization");
    const org = await orgBySlug(deps, slug);
    if (!org) return c.json(rpcError(null, -32000, "Unknown organization"), 404);

    const text = await c.req.text();
    if (text.length > MAX_BODY) return c.json(rpcError(null, -32600, "The request is too large"), 413);
    let msg: Rpc;
    try {
      msg = JSON.parse(text) as Rpc;
    } catch {
      return c.json(rpcError(null, -32700, "Parse error"), 400);
    }
    if (Array.isArray(msg)) return c.json(rpcError(null, -32600, "Batching isn't supported"), 400);
    if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return c.json(rpcError(msg?.id, -32600, "Invalid request"), 400);

    // Authenticate and load everything needed to decide, in one short transaction.
    const ctx = await deps.db.tenant(org.org_id, async (tx) => {
      const server = await loadServer(tx, serverSlug);
      if (!server) return { kind: "no_server" as const };
      const who = await verifyCaller(tx, deps, org.org_id, { token: header.slice(7), issuer: issuerFor(deps, slug), slug, serverUrl: serverUrl(deps, slug, serverSlug) });
      if ("error" in who) return { kind: "unauthorized" as const, error: who.error };
      if (who.kind === "agent") await touchAgent(tx, who.agentId);
      return { kind: "ok" as const, server, who, rules: await rulesFor(tx, server.id), tools: await tx.selectFrom("mcp_tools").selectAll().where("server_id", "=", server.id).execute(), dlp: await loadMcpDlp(tx) };
    });
    if (ctx.kind === "no_server") return c.json(rpcError(msg.id, -32000, "Unknown MCP server"), 404);
    if (ctx.kind === "unauthorized") return unauthorized(c, deps, slug, serverSlug, ctx.error);
    const { server, who, rules, tools, dlp } = ctx;
    if (server.status !== "active") return c.json(rpcError(msg.id, -32000, `${server.name} is disabled in Votal Nexus`), 503);

    // Notifications and responses from the client: acknowledged, nothing to return.
    if (msg.id === undefined || msg.id === null) return c.body(null, 202);

    const caller = policyCaller(who);
    switch (msg.method) {
      case "initialize": {
        const asked = String(msg.params?.protocolVersion ?? "");
        return c.json(
          rpcResult(msg.id, {
            protocolVersion: SUPPORTED_VERSIONS.includes(asked) ? asked : SUPPORTED_VERSIONS[0],
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: `${server.name} (via Votal Nexus)`, version: VERSION },
            instructions: server.description || undefined,
          }),
        );
      }
      case "ping":
        return c.json(rpcResult(msg.id, {}));
      case "tools/list": {
        const visible = tools
          .filter((t) => authorize(t as Tool, rules, caller, null).allow)
          .sort((a, b) => a.name.localeCompare(b.name))
          .map((t) => ({
            name: t.name,
            ...(t.title ? { title: t.title } : {}),
            description: t.description,
            inputSchema: Object.keys(t.input_schema as object).length ? t.input_schema : { type: "object" },
            ...(Object.keys(t.annotations as object).length ? { annotations: t.annotations } : {}),
          }));
        return c.json(rpcResult(msg.id, { tools: visible }));
      }
      case "tools/call":
        return c.json(await callTool(deps, org.org_id, meta, server, who, tools, rules, dlp, msg));
      default:
        return c.json(rpcError(msg.id, -32601, `Method not found: ${msg.method}`));
    }
  });
}

type ServerRow = NonNullable<Awaited<ReturnType<typeof loadServer>>>;
type ToolRow = Tool & { id: string };

/** An agent's token or a person's: same signing keys and audience rules, different principals. */
async function verifyCaller(tx: Tx, deps: Deps, orgId: string, a: { token: string; issuer: string; slug: string; serverUrl: string }): Promise<GatewayCaller | { error: string }> {
  const jwks = createLocalJWKSet(await publicJwks(tx, deps, orgId));
  const verified = await jwtVerify(a.token, jwks, { issuer: a.issuer, audience: [gatewayBase(deps, a.slug), a.serverUrl], typ: "at+jwt" }).catch(() => null);
  if (!verified) return { error: "The access token is invalid, expired, or for another resource" };
  if (verified.payload.nexus_principal === "user") return verifyUserToken(tx, verified.payload);
  const agent = await verifyAgentToken(tx, deps, orgId, a);
  return "error" in agent ? agent : { kind: "agent", ...agent };
}

async function callTool(deps: Deps, orgId: string, meta: Env["Variables"]["meta"], server: ServerRow, who: GatewayCaller, tools: ToolRow[], rules: Rule[], dlp: McpDlp, msg: Rpc) {
  const name = String(msg.params?.name ?? "");
  const args = (msg.params?.arguments ?? {}) as Record<string, unknown>;
  if (typeof args !== "object" || Array.isArray(args)) return rpcError(msg.id, -32602, "arguments must be an object");
  const tool = tools.find((t) => t.name === name);
  const started = performance.now();

  const trace = (decision: Decision, extra: Record<string, unknown>) =>
    deps.db.tenant(orgId, (tx) =>
      audit(tx, orgId, { meta }, {
        type: decision.allow ? "mcp.tool_called" : "mcp.tool_denied",
        outcome: !decision.allow ? "denied" : extra.upstream && extra.upstream !== "ok" ? "failure" : "success",
        actor: auditActor(who),
        target: { type: "mcp_tool", id: tool?.id ?? null, display: `${server.slug}/${name}` },
        details: {
          server_id: server.id,
          server: server.name,
          tool: name,
          risk: tool?.risk ?? null,
          decision: decision.allow ? "allow" : "deny",
          reason: decision.reason,
          rule_id: decision.rule_id,
          args_hash: argsHash(args),
          args_keys: Object.keys(args).slice(0, 50),
          ...(who.kind === "agent" ? { token_jti: who.jti } : { via: who.clientName, grant_id: who.grantId }),
          ...extra,
        },
      }),
    );

  if (!tool) return rpcError(msg.id, -32602, `Unknown tool: ${name}`);

  // Rate limit per agent and server (MCP-07). The first refusal in a minute is traced, not every one.
  if (!(await limiter(server.calls_per_minute).take(`${server.id}:${callerKey(who)}`))) {
    const key = `${server.id}:${callerKey(who)}`;
    if (Date.now() - (rateNoted.get(key) ?? 0) > 60_000) {
      rateNoted.set(key, Date.now());
      await trace({ allow: false, reason: `Rate limit: ${server.calls_per_minute} calls a minute`, rule_id: null }, { rate_limited: true });
    }
    return rpcError(msg.id, -32000, `Rate limit exceeded: ${server.calls_per_minute} calls a minute. Slow down and retry.`);
  }

  const decision = authorize(tool as Tool, rules, policyCaller(who), args);
  if (!decision.allow) {
    await trace(decision, {});
    return rpcResult(msg.id, { content: [{ type: "text", text: `Votal Nexus denied this call: ${decision.reason}.` }], isError: true });
  }

  // Data protection on what leaves: a secret in the arguments stops the call.
  const argCheck = checkArguments(dlp, args);
  if (argCheck.block) {
    const refused = { allow: false, reason: `The arguments contain ${argCheck.block}`, rule_id: null };
    await trace(refused, { dlp_arguments: argCheck.notes });
    return rpcResult(msg.id, { content: [{ type: "text", text: `Votal Nexus stopped this call: the arguments contain ${argCheck.block}. Remove it and try again.` }], isError: true });
  }

  try {
    const raw = await upstreamRequest(upstreamConfig(deps, server), "tools/call", { name, arguments: args });
    // …and on what the AI is about to read: redacted before it gets it.
    const protectedResult = protectResult(dlp, raw);
    const ms = Math.round(performance.now() - started);
    await trace(decision, {
      latency_ms: ms,
      upstream: "ok",
      is_error: !!(raw as { isError?: boolean })?.isError,
      ...(argCheck.notes.length ? { dlp_arguments: argCheck.notes } : {}),
      ...(protectedResult.notes.length ? { dlp_results: protectedResult.notes } : {}),
    });
    return rpcResult(msg.id, protectedResult.result);
  } catch (e) {
    const ms = Math.round(performance.now() - started);
    const ue = e instanceof UpstreamError ? e : null;
    await trace(decision, { latency_ms: ms, upstream: ue?.kind ?? "error", error: (e as Error).message.slice(0, 300) });
    if (ue?.kind === "rpc" && ue.rpc) return rpcError(msg.id, ue.rpc.code, ue.rpc.message, ue.rpc.data);
    return rpcError(msg.id, -32603, `${server.name} couldn't be reached: ${(e as Error).message}`);
  }
}

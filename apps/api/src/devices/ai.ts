import { z } from "@hono/zod-openapi";
import type { Tx } from "../platform/db.js";

/**
 * AI on devices: the AI tools and MCP servers the agent finds in each
 * account's AI clients (Claude Desktop, Claude Code, Cursor, VS Code…).
 * Nexus classifies every MCP server against the organization's MCP gateway:
 *
 * - gateway:  goes through this organization's Nexus MCP gateway (governed)
 * - bypass:   connects straight to a server the organization put behind the gateway
 * - allowed:  a remote host an admin allowed in the policy
 * - remote:   any other remote server (ungoverned)
 * - local:    runs on the device (stdio)
 */

const s = (max: number) => z.string().max(max);

export const AIInventory = z
  .object({
    tools: z.array(z.object({ name: s(100), kind: z.enum(["app", "cli", "extension"]), version: s(40).optional(), user: s(100).optional() })).max(100),
    mcp_servers: z
      .array(
        z.object({
          client: s(50),
          user: s(100),
          scope: z.enum(["user", "project"]),
          name: s(200),
          transport: z.enum(["stdio", "http", "sse"]),
          url: s(200).optional(),
          command: s(200).optional(),
          package: s(200).optional(),
          env_keys: z.array(s(200)).max(30).optional(),
          inline_secrets: z.boolean().optional(),
          disabled: z.boolean().optional(),
        }),
      )
      .max(300),
  })
  .openapi("AIInventory");
export type AIInventory = z.infer<typeof AIInventory>;
export type ReportedServer = AIInventory["mcp_servers"][number];

export const GOVERNANCE = ["gateway", "bypass", "allowed", "remote", "local"] as const;
export type Governance = (typeof GOVERNANCE)[number];

/** What classification needs to know about the organization. */
export type AIContext = { gatewayPrefix: string; upstreams: { url: string; name: string }[] };

let apiBase = "";
/** The API's public URL, which agents' MCP clients use to reach the gateway (set at startup). */
export function setGatewayBase(url: string) {
  apiBase = url.replace(/\/+$/, "").toLowerCase();
}

/** host + path, lowercased, without trailing slash: how two MCP URLs are compared. */
export function urlKey(raw: string) {
  try {
    const u = new URL(raw);
    return `${u.host.toLowerCase()}${u.pathname.replace(/\/+$/, "").toLowerCase()}`;
  } catch {
    return raw.toLowerCase();
  }
}

export async function loadAIContext(tx: Tx): Promise<AIContext> {
  const org = await tx.selectFrom("organizations").select("slug").executeTakeFirst();
  const upstreams = await tx.selectFrom("mcp_servers").select(["url", "name"]).execute();
  return { gatewayPrefix: org ? urlKey(`${apiBase}/mcp/${org.slug}`) : "", upstreams };
}

export function classify(server: Pick<ReportedServer, "transport" | "url">, ctx: AIContext, allowedHosts: string[] = []): { governance: Governance; via?: string } {
  if (!server.url) return { governance: "local" };
  const key = urlKey(server.url);
  if (ctx.gatewayPrefix && (key === ctx.gatewayPrefix || key.startsWith(`${ctx.gatewayPrefix}/`))) return { governance: "gateway" };
  const up = ctx.upstreams.find((u) => urlKey(u.url) === key);
  if (up) return { governance: "bypass", via: up.name };
  let host = "";
  try {
    host = new URL(server.url).hostname.toLowerCase();
  } catch {
    /* unparseable: stays remote */
  }
  // An HTTP server on the device itself (loopback) is local, like a stdio one.
  if (/^(localhost|127(\.\d{1,3}){3}|\[?::1\]?|0\.0\.0\.0)$/.test(host)) return { governance: "local" };
  if (host && allowedHosts.some((h) => hostMatches(host, h))) return { governance: "allowed" };
  return { governance: "remote" };
}

/** "mcp.corp.com" matches exactly; "*.corp.com" matches any subdomain. */
export function hostMatches(host: string, pattern: string) {
  const p = pattern.trim().toLowerCase();
  return p.startsWith("*.") ? host.endsWith(p.slice(1)) : host === p;
}

/** A stable identity for "the same server" across devices: its URL, package or command. */
export function serverKey(x: Pick<ReportedServer, "url" | "package" | "command" | "name">) {
  if (x.url) return `url:${urlKey(x.url)}`;
  if (x.package) return `pkg:${x.package.toLowerCase()}`;
  return `cmd:${(x.command || x.name).toLowerCase()}`;
}

/** The target to show people: host/path, package, or command. */
export const serverTarget = (x: Pick<ReportedServer, "url" | "package" | "command">) => (x.url ? urlKey(x.url) : x.package || x.command || "");

/** Added and removed servers between two reports (for the audit log). */
export function diffServers(before: AIInventory | null, after: AIInventory) {
  const id = (x: ReportedServer) => `${x.user}|${x.client}|${x.scope}|${x.name}|${serverKey(x)}`;
  const was = new Map((before?.mcp_servers ?? []).map((x) => [id(x), x]));
  const now = new Map(after.mcp_servers.map((x) => [id(x), x]));
  const added = [...now].filter(([k]) => !was.has(k)).map(([, x]) => x);
  const removed = [...was].filter(([k]) => !now.has(k)).map(([, x]) => x);
  return { added, removed, first: before === null };
}

export const parseAI = (inventory: unknown): AIInventory | null => AIInventory.safeParse((inventory as { ai?: unknown } | null)?.ai).data ?? null;

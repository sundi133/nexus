import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App } from "../context.js";
import { requirePermission, scopeGroups } from "../auth/guard.js";
import { notPrivileged } from "../directory/privileged.js";
import type { Tx } from "../platform/db.js";
import { bearer, json, problemResponses } from "../schemas.js";
import { type AIContext, type AIInventory, classify, GOVERNANCE, type Governance, loadAIContext, parseAI, type ReportedServer, serverKey, serverTarget } from "./ai.js";
import { getPolicies } from "./service.js";

/** AI on devices: which AI tools and MCP servers people use, across the fleet and per device. */

const Gov = z.enum(GOVERNANCE).openapi({ description: "gateway: through the Nexus MCP gateway; bypass: straight to a server that's behind the gateway; allowed: a host the policy allows; remote: any other remote server; local: runs on the device" });

export const DeviceServer = z
  .object({
    client: z.string(),
    user: z.string(),
    scope: z.enum(["user", "project"]),
    name: z.string(),
    transport: z.enum(["stdio", "http", "sse"]),
    target: z.string(),
    package: z.string().nullable(),
    env_keys: z.array(z.string()),
    inline_secrets: z.boolean(),
    disabled: z.boolean(),
    governance: Gov,
    via: z.string().nullable().openapi({ description: "For bypass: the gateway server it should go through" }),
  })
  .openapi("DeviceMcpServer");

export const DeviceAI = z
  .object({
    tools: z.array(z.object({ name: z.string(), kind: z.enum(["app", "cli", "extension"]), version: z.string().nullable(), user: z.string().nullable() })),
    mcp_servers: z.array(DeviceServer),
  })
  .nullable()
  .openapi("DeviceAI", { description: "What the agent found in the device's AI clients; null until an agent that reports it checks in" });

async function allowedHosts(tx: Tx) {
  const p = (await getPolicies(tx)).find((x) => x.key === "ai_mcp_governed");
  return ((p?.params as { allowed_hosts?: string[] })?.allowed_hosts ?? []) as string[];
}

export function deviceServer(x: ReportedServer, ctx: AIContext, allowed: string[]): z.infer<typeof DeviceServer> {
  const c = classify(x, ctx, allowed);
  return {
    client: x.client,
    user: x.user,
    scope: x.scope,
    name: x.name,
    transport: x.transport,
    target: serverTarget(x),
    package: x.package ?? null,
    env_keys: x.env_keys ?? [],
    inline_secrets: !!x.inline_secrets,
    disabled: !!x.disabled,
    governance: c.governance,
    via: c.via ?? null,
  };
}

/** For the device detail page. */
export async function deviceAI(tx: Tx, inventory: unknown): Promise<z.infer<typeof DeviceAI>> {
  const ai = parseAI(inventory);
  if (!ai) return null;
  const [ctx, allowed] = [await loadAIContext(tx), await allowedHosts(tx)];
  return {
    tools: ai.tools.map((t) => ({ name: t.name, kind: t.kind, version: t.version ?? null, user: t.user ?? null })),
    mcp_servers: ai.mcp_servers.map((x) => deviceServer(x, ctx, allowed)),
  };
}

const RANK: Record<Governance, number> = { bypass: 0, remote: 1, allowed: 2, local: 3, gateway: 4 };

const FleetServer = z
  .object({
    key: z.string(),
    target: z.string(),
    transport: z.enum(["stdio", "http", "sse"]),
    governance: Gov,
    via: z.string().nullable(),
    names: z.array(z.string()),
    clients: z.array(z.string()),
    devices: z.number().int(),
    people: z.number().int(),
    inline_secrets: z.number().int().openapi({ description: "Devices where this server's config holds a token in plain text" }),
    on: z.array(z.object({ device_id: z.string(), hostname: z.string(), user_email: z.string().nullable(), clients: z.array(z.string()), inline_secrets: z.boolean() })).openapi({ description: "Up to 100 devices" }),
  })
  .openapi("FleetMcpServer");

const Fleet = z
  .object({
    summary: z.object({
      devices: z.number().int(),
      reporting: z.number().int().openapi({ description: "Devices whose agent reports AI tools" }),
      with_ai_tools: z.number().int(),
      with_mcp: z.number().int(),
      ungoverned: z.number().int().openapi({ description: "Devices with an enabled MCP server that bypasses the gateway or uses a remote server that isn't allowed" }),
      inline_secrets: z.number().int().openapi({ description: "Devices with a token written into an MCP config file" }),
    }),
    servers: z.array(FleetServer),
    tools: z.array(z.object({ name: z.string(), kind: z.enum(["app", "cli", "extension"]), devices: z.number().int(), versions: z.array(z.string()) })),
  })
  .openapi("AIFleetInventory");

export function registerAIRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/devices/ai-inventory",
      tags: ["Devices"],
      summary: "AI tools and MCP servers across devices",
      description: "Aggregates what agents find in AI clients (Claude, Cursor, VS Code, Codex…): each MCP server with how it's governed, and each AI app, CLI and extension.",
      security: bearer,
      responses: { 200: json(Fleet), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const scope = scopeGroups(p, "devices:read");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        let q = tx
          .selectFrom("devices")
          .leftJoin("users", "users.id", "devices.primary_user_id")
          .select(["devices.id", "devices.hostname", "devices.primary_user_id", "users.email"])
          .select(sql<unknown>`jsonb_build_object('ai', devices.inventory->'ai')`.as("inv"))
          .where("devices.status", "=", "active");
        if (scope) q = q.where((eb) => eb.exists(eb.selectFrom("group_members").whereRef("group_members.user_id", "=", "devices.primary_user_id").where("group_members.group_id", "in", scope))).where(notPrivileged("devices.primary_user_id"));
        const rows = await q.orderBy("devices.hostname").execute();
        const [ctx, allowed] = [await loadAIContext(tx), await allowedHosts(tx)];
        return aggregate(rows.map((r) => ({ id: r.id, hostname: r.hostname, person: r.primary_user_id, email: r.email, ai: parseAI(r.inv) })), ctx, allowed);
      });
      return c.json(out, 200);
    },
  );
}

type FleetDevice = { id: string; hostname: string; person: string | null; email: string | null; ai: AIInventory | null };

export function aggregate(devices: FleetDevice[], ctx: AIContext, allowed: string[]): z.infer<typeof Fleet> {
  const servers = new Map<string, { s: z.infer<typeof FleetServer>; people: Set<string>; byDevice: Map<string, { clients: Set<string>; secrets: boolean }> }>();
  const tools = new Map<string, { name: string; kind: "app" | "cli" | "extension"; devices: Set<string>; versions: Set<string> }>();
  const summary = { devices: devices.length, reporting: 0, with_ai_tools: 0, with_mcp: 0, ungoverned: 0, inline_secrets: 0 };
  const hostOf = new Map(devices.map((d) => [d.id, d]));

  for (const d of devices) {
    if (!d.ai) continue;
    summary.reporting++;
    if (d.ai.tools.length) summary.with_ai_tools++;
    const active = d.ai.mcp_servers.filter((x) => !x.disabled);
    if (active.length) summary.with_mcp++;
    let ungoverned = false;
    let secrets = false;
    for (const x of active) {
      const ds = deviceServer(x, ctx, allowed);
      if (ds.governance === "bypass" || ds.governance === "remote") ungoverned = true;
      if (ds.inline_secrets) secrets = true;
      const key = serverKey(x);
      let e = servers.get(key);
      if (!e) {
        e = { s: { key, target: ds.target, transport: x.transport, governance: ds.governance, via: ds.via, names: [], clients: [], devices: 0, people: 0, inline_secrets: 0, on: [] }, people: new Set(), byDevice: new Map() };
        servers.set(key, e);
      }
      if (!e.s.names.includes(x.name) && e.s.names.length < 5) e.s.names.push(x.name);
      if (!e.s.clients.includes(x.client)) e.s.clients.push(x.client);
      e.people.add(d.person ?? `device:${d.id}`);
      const on = e.byDevice.get(d.id) ?? { clients: new Set<string>(), secrets: false };
      on.clients.add(x.client);
      on.secrets ||= ds.inline_secrets;
      e.byDevice.set(d.id, on);
    }
    if (ungoverned) summary.ungoverned++;
    if (secrets) summary.inline_secrets++;
    for (const t of d.ai.tools) {
      const k = `${t.name}|${t.kind}`;
      const e = tools.get(k) ?? { name: t.name, kind: t.kind, devices: new Set<string>(), versions: new Set<string>() };
      e.devices.add(d.id);
      if (t.version) e.versions.add(t.version);
      tools.set(k, e);
    }
  }

  const list = [...servers.values()].map(({ s, people, byDevice }) => {
    const on = [...byDevice].map(([id, v]) => ({ device_id: id, hostname: hostOf.get(id)!.hostname, user_email: hostOf.get(id)!.email, clients: [...v.clients].sort(), inline_secrets: v.secrets }));
    return { ...s, names: s.names.sort(), clients: s.clients.sort(), devices: byDevice.size, people: people.size, inline_secrets: on.filter((o) => o.inline_secrets).length, on: on.sort((a, b) => a.hostname.localeCompare(b.hostname)).slice(0, 100) };
  });
  list.sort((a, b) => RANK[a.governance] - RANK[b.governance] || b.devices - a.devices || a.target.localeCompare(b.target));
  return {
    summary,
    servers: list,
    tools: [...tools.values()]
      .map((t) => ({ name: t.name, kind: t.kind, devices: t.devices.size, versions: [...t.versions].sort().slice(-5) }))
      .sort((a, b) => b.devices - a.devices || a.name.localeCompare(b.name)),
  };
}

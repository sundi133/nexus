import { sql } from "kysely";
import type { Tx } from "../platform/db.js";
import { type AIContext, classify, loadAIContext, parseAI, serverKey, serverTarget } from "../devices/ai.js";
import { getPolicies } from "../devices/service.js";
import { authorize, isUsable, type Rule, type Tool } from "../mcp/policy.js";

/**
 * The access graph (person → devices → AI clients → MCP servers → tools, and
 * person → owned AI agents → gateway tools) and an explainable risk score per
 * person. Every point comes from a named factor with a reason, so a score is
 * never a black box: it says what to fix.
 */

export type Level = "low" | "medium" | "high" | "critical";
export type Factor = { key: string; points: number; title: string; detail: string; device?: { id: string; hostname: string } };
export const levelOf = (score: number): Level => (score >= 70 ? "critical" : score >= 45 ? "high" : score >= 20 ? "medium" : "low");

// Base points, and the most a factor adds up to across several devices.
const WEIGHT: Record<string, { points: number; cap: number }> = {
  no_mfa: { points: 25, cap: 25 },
  admin_no_mfa: { points: 15, cap: 15 },
  admin: { points: 15, cap: 15 },
  delegated_admin: { points: 5, cap: 5 },
  noncompliant: { points: 20, cap: 30 },
  compliance_unknown: { points: 5, cap: 10 },
  mcp_bypass: { points: 30, cap: 40 },
  mcp_ungoverned: { points: 15, cap: 25 },
  mcp_secrets: { points: 20, cap: 30 },
  blocked_apps: { points: 10, cap: 15 },
  agent_destructive: { points: 15, cap: 20 },
  agent_external: { points: 5, cap: 10 },
};

type DeviceRow = { id: string; hostname: string; platform: string; compliance: string; primary_user_id: string | null; ai: unknown; failing: string[] };
type ToolRow = Tool & { id: string; server_id: string };
type AgentRow = { id: string; name: string; owner_user_id: string | null; status: string; tags: string[]; environment: string };
type ServerRow = { id: string; name: string; slug: string; status: string };

async function load(tx: Tx) {
  const [users, roles, mfa, devices, blocked, ctx, policies, agents, servers, tools, perms] = await Promise.all([
    tx.selectFrom("users").select(["id", "email", "given_name", "family_name"]).where("status", "=", "active").execute(),
    tx.selectFrom("user_roles").select(["user_id", "role"]).execute(),
    tx.selectFrom("auth_factors").select("user_id").distinct().where("verified_at", "is not", null).execute(),
    sql<DeviceRow>`
      SELECT d.id, d.hostname, d.platform, d.compliance, d.primary_user_id, d.inventory->'ai' AS ai,
             coalesce((SELECT array_agg(c.check_key ORDER BY c.check_key) FROM device_checks c WHERE c.device_id = d.id AND c.status = 'fail' AND c.enforced), '{}') AS failing
      FROM devices d WHERE d.status = 'active'`.execute(tx),
    tx
      .selectFrom("enforcement_events")
      .select(["device_id", (eb) => eb.fn.sum<number>("count").as("n")])
      .where("action", "in", ["terminated", "would_terminate"])
      .where("occurred_at", ">", new Date(Date.now() - 7 * 86_400_000))
      .groupBy("device_id")
      .execute(),
    loadAIContext(tx),
    getPolicies(tx),
    tx.selectFrom("ai_agents").select(["id", "name", "owner_user_id", "status", "tags", "environment"]).execute() as Promise<AgentRow[]>,
    tx.selectFrom("mcp_servers").select(["id", "name", "slug", "status"]).execute() as Promise<ServerRow[]>,
    tx.selectFrom("mcp_tools").select(["id", "server_id", "name", "status", "risk", "hash", "approved_hash"]).where("status", "!=", "removed").execute() as Promise<ToolRow[]>,
    tx.selectFrom("mcp_permissions").selectAll().execute(),
  ]);
  const allowed = ((policies.find((p) => p.key === "ai_mcp_governed")?.params as { allowed_hosts?: string[] })?.allowed_hosts ?? []) as string[];
  const rulesByServer = new Map<string, Rule[]>();
  for (const p of perms) {
    const list = rulesByServer.get(p.server_id) ?? [];
    list.push({ id: p.id, effect: p.effect, subject_type: p.subject_type, subject_id: p.subject_id, subject_tag: p.subject_tag, tools: p.tools, risks: p.risks, conditions: (p.conditions as unknown as Rule["conditions"]) ?? [] } as Rule);
    rulesByServer.set(p.server_id, list);
  }
  return {
    users,
    roles: groupBy(roles, (r) => r.user_id, (r) => r.role),
    mfa: new Set(mfa.map((m) => m.user_id)),
    devices: devices.rows,
    blocked: new Map(blocked.map((b) => [b.device_id, Number(b.n)])),
    ctx,
    allowed,
    agents,
    servers,
    tools,
    rulesByServer,
  };
}
type Data = Awaited<ReturnType<typeof load>>;

function groupBy<T, V>(xs: T[], key: (x: T) => string, val: (x: T) => V) {
  const m = new Map<string, V[]>();
  for (const x of xs) m.set(key(x), [...(m.get(key(x)) ?? []), val(x)]);
  return m;
}

/** What an agent may use through the gateway: per Nexus MCP server, the usable tools its rules allow. */
function agentReach(d: Data, a: AgentRow) {
  const out: { server: ServerRow; tools: ToolRow[] }[] = [];
  if (a.status !== "active") return out;
  for (const s of d.servers) {
    if (s.status !== "active") continue;
    const rules = d.rulesByServer.get(s.id) ?? [];
    const tools = d.tools.filter((t) => t.server_id === s.id && isUsable(t) && authorize(t, rules, { agentId: a.id, tags: a.tags }, null).allow);
    if (tools.length) out.push({ server: s, tools });
  }
  return out;
}

function deviceFactors(d: Data, dev: DeviceRow): Factor[] {
  const at = { id: dev.id, hostname: dev.hostname };
  const out: Factor[] = [];
  if (dev.compliance === "non_compliant") out.push({ key: "noncompliant", points: WEIGHT.noncompliant!.points, title: "Device isn't compliant", detail: `${dev.hostname} fails ${dev.failing.join(", ").replaceAll("_", " ") || "a policy"}`, device: at });
  else if (dev.compliance === "unknown") out.push({ key: "compliance_unknown", points: WEIGHT.compliance_unknown!.points, title: "Device compliance unknown", detail: `${dev.hostname} hasn't reported everything policies check`, device: at });
  const ai = parseAI({ ai: dev.ai });
  const active = ai?.mcp_servers.filter((s) => !s.disabled) ?? [];
  const cls = active.map((s) => ({ s, c: classify(s, d.ctx, d.allowed) }));
  const bypass = cls.filter((x) => x.c.governance === "bypass");
  const remote = cls.filter((x) => x.c.governance === "remote");
  const secrets = active.filter((s) => s.inline_secrets);
  const names = (xs: { s: { name: string; client: string } }[]) => xs.slice(0, 3).map((x) => `${x.s.name} (${x.s.client})`).join(", ") + (xs.length > 3 ? ` and ${xs.length - 3} more` : "");
  if (bypass.length) out.push({ key: "mcp_bypass", points: WEIGHT.mcp_bypass!.points, title: "MCP server bypasses the Nexus gateway", detail: `${names(bypass)} on ${dev.hostname} connect straight to servers you govern through the gateway`, device: at });
  if (remote.length) out.push({ key: "mcp_ungoverned", points: Math.min(WEIGHT.mcp_ungoverned!.cap, WEIGHT.mcp_ungoverned!.points + 5 * (remote.length - 1)), title: "Ungoverned MCP servers", detail: `${names(remote)} on ${dev.hostname} aren't behind the gateway`, device: at });
  if (secrets.length) out.push({ key: "mcp_secrets", points: WEIGHT.mcp_secrets!.points, title: "Tokens written into MCP config files", detail: `${names(secrets.map((s) => ({ s })))} on ${dev.hostname}`, device: at });
  const blocked = d.blocked.get(dev.id) ?? 0;
  if (blocked) out.push({ key: "blocked_apps", points: WEIGHT.blocked_apps!.points, title: "Keeps starting blocked apps", detail: `${blocked} times in 7 days on ${dev.hostname}`, device: at });
  return out;
}

/** Same factor on several devices: the strongest, plus 5 per extra device, up to the factor's cap. */
function combine(factors: Factor[]) {
  const byKey = groupBy(factors, (f) => f.key, (f) => f);
  const merged: Factor[] = [];
  for (const [key, fs] of byKey) {
    const top = fs.reduce((a, b) => (b.points > a.points ? b : a));
    const points = Math.min(WEIGHT[key]?.cap ?? top.points, top.points + 5 * (fs.length - 1));
    merged.push(fs.length === 1 ? top : { ...top, points, detail: fs.map((f) => f.detail).join("; "), device: undefined });
  }
  return merged.sort((a, b) => b.points - a.points);
}

export type PersonRisk = {
  user_id: string;
  email: string;
  name: string;
  score: number;
  level: Level;
  factors: Factor[];
  devices: number;
  ai_clients: number;
  mcp_servers: number;
  agents: number;
};

export async function computeRisk(tx: Tx): Promise<PersonRisk[]> {
  const d = await load(tx);
  const devicesOf = groupBy(d.devices.filter((x) => x.primary_user_id), (x) => x.primary_user_id!, (x) => x);
  const agentsOf = groupBy(d.agents.filter((a) => a.owner_user_id), (a) => a.owner_user_id!, (a) => a);
  return d.users
    .map((u) => {
      const roles = d.roles.get(u.id) ?? [];
      const factors: Factor[] = [];
      const hasMfa = d.mfa.has(u.id);
      const topAdmin = roles.some((r) => r === "owner" || r === "admin");
      if (topAdmin) factors.push({ key: "admin", points: WEIGHT.admin!.points, title: "Administrator", detail: `Holds ${roles.filter((r) => r === "owner" || r === "admin").join(" and ")}: a takeover reaches the whole organization` });
      else if (roles.length) factors.push({ key: "delegated_admin", points: WEIGHT.delegated_admin!.points, title: "Delegated admin rights", detail: roles.join(", ") });
      if (!hasMfa) factors.push({ key: "no_mfa", points: WEIGHT.no_mfa!.points, title: "No MFA", detail: "A stolen password is enough to sign in" });
      if (!hasMfa && roles.length) factors.push({ key: "admin_no_mfa", points: WEIGHT.admin_no_mfa!.points, title: "Admin without MFA", detail: "An admin account protected only by a password" });
      const devs = devicesOf.get(u.id) ?? [];
      for (const dev of devs) factors.push(...deviceFactors(d, dev));
      const agents = (agentsOf.get(u.id) ?? []).filter((a) => a.status === "active");
      for (const a of agents) {
        const reach = agentReach(d, a).flatMap((r) => r.tools);
        const destructive = reach.filter((t) => t.risk === "destructive");
        const external = reach.filter((t) => t.risk === "external");
        if (destructive.length) factors.push({ key: "agent_destructive", points: WEIGHT.agent_destructive!.points, title: "Owns an agent that can take destructive actions", detail: `${a.name} may use ${destructive.slice(0, 3).map((t) => t.name).join(", ")}${destructive.length > 3 ? ` and ${destructive.length - 3} more` : ""}` });
        else if (external.length) factors.push({ key: "agent_external", points: WEIGHT.agent_external!.points, title: "Owns an agent that acts outside the company", detail: `${a.name} may use ${external.slice(0, 3).map((t) => t.name).join(", ")}` });
      }
      const merged = combine(factors);
      const score = Math.min(100, merged.reduce((n, f) => n + f.points, 0));
      const servers = new Set<string>();
      const clients = new Set<string>();
      for (const dev of devs) {
        for (const s of parseAI({ ai: dev.ai })?.mcp_servers.filter((x) => !x.disabled) ?? []) {
          servers.add(serverKey(s));
          clients.add(`${dev.id}|${s.client}|${s.user}`);
        }
      }
      return {
        user_id: u.id,
        email: u.email,
        name: `${u.given_name} ${u.family_name}`.trim() || u.email,
        score,
        level: levelOf(score),
        factors: merged,
        devices: devs.length,
        ai_clients: clients.size,
        mcp_servers: servers.size,
        agents: agents.length,
      };
    })
    .sort((a, b) => b.score - a.score || a.email.localeCompare(b.email));
}

// ---- The graph for one person ------------------------------------------------------------------

export type Node = {
  id: string;
  type: "person" | "device" | "client" | "server" | "gateway_server" | "tools" | "agent";
  column: number;
  label: string;
  sublabel: string;
  tone: "neutral" | "success" | "warning" | "danger";
  href?: string;
};
export type Edge = { from: string; to: string; label: string; tone: "neutral" | "success" | "warning" | "danger"; dashed?: boolean };

const GOV_TONE = { gateway: "success", allowed: "neutral", local: "neutral", remote: "warning", bypass: "danger" } as const;
const GOV_LABEL = { gateway: "via Nexus", allowed: "allowed host", local: "local", remote: "ungoverned", bypass: "bypasses gateway" } as const;

function toolsSummary(tools: ToolRow[]) {
  const by = (r: string) => tools.filter((t) => t.risk === r).length;
  const parts = [["destructive", by("destructive")], ["external", by("external")], ["write", by("write")], ["read", by("read")]].filter(([, n]) => n) as [string, number][];
  return { text: parts.map(([r, n]) => `${n} ${r}`).join(", "), tone: by("destructive") ? ("danger" as const) : by("external") ? ("warning" as const) : ("neutral" as const) };
}

export async function graphFor(tx: Tx, userId: string, ctxOverride?: AIContext) {
  const d = await load(tx);
  if (ctxOverride) d.ctx = ctxOverride;
  const u = d.users.find((x) => x.id === userId);
  if (!u) return null;
  const nodes = new Map<string, Node>();
  const edges: Edge[] = [];
  const add = (n: Node) => (nodes.has(n.id) ? nodes.get(n.id)! : (nodes.set(n.id, n), n));
  const person = add({ id: `user:${u.id}`, type: "person", column: 0, label: `${u.given_name} ${u.family_name}`.trim() || u.email, sublabel: u.email, tone: "neutral", href: `/users/${u.id}` });
  const slugOf = (url: string) => new URL(url).pathname.split("/").filter(Boolean)[2] ?? "";
  const gatewayNode = (s: ServerRow) => {
    const tools = d.tools.filter((t) => t.server_id === s.id && isUsable(t));
    const n = add({ id: `nexus:${s.id}`, type: "gateway_server", column: 4, label: s.name, sublabel: `Nexus gateway · ${tools.length} approved tools`, tone: s.status === "active" ? "success" : "neutral", href: `/mcp/${s.id}` });
    const sum = toolsSummary(tools);
    if (tools.length) {
      const t = add({ id: `tools:${s.id}`, type: "tools", column: 5, label: `${tools.length} tools`, sublabel: sum.text, tone: sum.tone });
      if (!edges.some((e) => e.from === n.id && e.to === t.id)) edges.push({ from: n.id, to: t.id, label: "", tone: sum.tone });
    }
    return n;
  };

  for (const dev of d.devices.filter((x) => x.primary_user_id === userId)) {
    const devNode = add({ id: `device:${dev.id}`, type: "device", column: 1, label: dev.hostname, sublabel: `${dev.platform} · ${dev.compliance.replace("_", "-")}`, tone: dev.compliance === "compliant" ? "success" : dev.compliance === "non_compliant" ? "danger" : "warning", href: `/devices/${dev.id}` });
    edges.push({ from: person.id, to: devNode.id, label: "uses", tone: "neutral" });
    const ai = parseAI({ ai: dev.ai });
    for (const s of ai?.mcp_servers.filter((x) => !x.disabled) ?? []) {
      const clientNode = add({ id: `client:${dev.id}:${s.client}:${s.user}`, type: "client", column: 2, label: s.client, sublabel: `on ${dev.hostname} · ${s.user}`, tone: "neutral", href: `/devices/${dev.id}` });
      if (!edges.some((e) => e.from === devNode.id && e.to === clientNode.id)) edges.push({ from: devNode.id, to: clientNode.id, label: "", tone: "neutral" });
      const c = classify(s, d.ctx, d.allowed);
      const key = serverKey(s);
      const srv = add({ id: `server:${key}`, type: "server", column: 3, label: serverTarget(s), sublabel: GOV_LABEL[c.governance], tone: GOV_TONE[c.governance] });
      if (s.inline_secrets && srv.tone !== "danger") srv.tone = "danger";
      if (s.inline_secrets && !srv.sublabel.includes("token")) srv.sublabel += " · token in config";
      const same = edges.find((e) => e.from === clientNode.id && e.to === srv.id);
      if (same) same.label = `${same.label}, ${s.name}`; // several entries for one server: one edge
      else edges.push({ from: clientNode.id, to: srv.id, label: s.name, tone: GOV_TONE[c.governance] });
      if (c.governance === "gateway") {
        const gs = d.servers.find((x) => x.slug === slugOf(s.url!));
        if (gs && !edges.some((e) => e.from === srv.id && e.to === `nexus:${gs.id}`)) edges.push({ from: srv.id, to: gatewayNode(gs).id, label: "policy + audit", tone: "success" });
      } else if (c.governance === "bypass" && c.via) {
        const gs = d.servers.find((x) => x.name === c.via);
        if (gs && !edges.some((e) => e.from === srv.id && e.to === `nexus:${gs.id}`)) edges.push({ from: srv.id, to: gatewayNode(gs).id, label: "should go through", tone: "danger", dashed: true });
      }
    }
  }
  for (const a of d.agents.filter((x) => x.owner_user_id === userId)) {
    const agentNode = add({ id: `agent:${a.id}`, type: "agent", column: 2, label: a.name, sublabel: `AI agent · ${a.environment}${a.status !== "active" ? " · suspended" : ""}`, tone: a.status === "active" ? "neutral" : "warning", href: `/agents/${a.id}` });
    edges.push({ from: person.id, to: agentNode.id, label: "owns", tone: "neutral" });
    for (const r of agentReach(d, a)) {
      const sum = toolsSummary(r.tools);
      edges.push({ from: agentNode.id, to: gatewayNode(r.server).id, label: `may use ${sum.text}`, tone: sum.tone });
    }
  }
  return { nodes: [...nodes.values()], edges };
}

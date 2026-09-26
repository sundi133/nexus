import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { evaluate } from "../src/alerts/engine.js";
import { newId } from "../src/platform/ids.js";
import { recomputeRisk } from "../src/risk/routes.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";
import { SoftDevice } from "./soft-device.js";

/** The access graph and risk scores: explainable factors, the graph, and alerts when someone's risk rises. */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let orgId = "";
let slug = "";
let samId = "";
let kimId = "";
let githubId = "";
const healthy = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 60 }, system_integrity: { status: "on" } };

async function agentCall(path: string, payload: unknown, proof: string) {
  const res = await h.app.request(path, { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${proof}` }, body: JSON.stringify(payload) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}
async function enrolled(hostname: string, userId: string) {
  const d = await new SoftDevice().init();
  const t = await h.call("POST", "/v1/devices/enrollment-tokens", { token: admin, body: { name: `t-${hostname}`, max_uses: 1 } });
  const payload = { token: t.body.token, device: { hostname, platform: "macos", os_name: "macOS", os_version: "15.1", os_build: "x", arch: "arm64", model: "M", serial: `S-${hostname}`, agent_version: "0.5.0" } };
  const r = await agentCall("/v1/agent/enroll", payload, await d.proof("/v1/agent/enroll", JSON.stringify(payload), { enroll: true }));
  d.id = r.body.device_id;
  await h.call("PATCH", `/v1/devices/${d.id}`, { token: admin, body: { primary_user_id: userId } });
  return d;
}
async function checkin(d: SoftDevice, posture: Record<string, unknown>, ai?: unknown) {
  const payload = { device: { agent_version: "0.5.0" }, posture, ...(ai ? { inventory: { ai } } : {}) };
  return agentCall("/v1/agent/checkin", payload, await d.proof("/v1/agent/checkin", JSON.stringify(payload)));
}
const people = async () => (await h.call("GET", "/v1/risk/people", { token: admin })).body.data as any[];
const of = async (id: string) => (await people()).find((p) => p.user_id === id);
const tenant = <T>(fn: (tx: any) => Promise<T>) => h.deps.db.tenant(orgId, fn);

let sam: SoftDevice;

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Risk Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token: admin })).body;
  orgId = me.organization.id;
  slug = me.organization.slug;
  samId = (await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("sam"), given_name: "Sam", family_name: "Lee" } })).body.id;
  kimId = (await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("kim"), given_name: "Kim" } })).body.id;
  // A GitHub MCP server behind the gateway, with a destructive and a read tool, and a rule letting every agent use them.
  githubId = newId();
  await tenant(async (tx) => {
    await tx.insertInto("mcp_servers").values({ id: githubId, org_id: orgId, name: "GitHub", slug: "github", url: "https://api.githubcopilot.com/mcp", server_info: JSON.stringify({}) }).execute();
    for (const [name, risk] of [["delete_repo", "destructive"], ["list_issues", "read"]] as const)
      await tx.insertInto("mcp_tools").values({ id: newId(), org_id: orgId, server_id: githubId, name, input_schema: JSON.stringify({}), annotations: JSON.stringify({}), hash: `h-${name}`, approved_hash: `h-${name}`, status: "approved", risk }).execute();
    await tx.insertInto("mcp_permissions").values({ id: newId(), org_id: orgId, server_id: githubId, effect: "allow", subject_type: "all_agents", subject_id: null, subject_tag: null, tools: ["*"], risks: null, conditions: JSON.stringify([]) }).execute();
    await tx.insertInto("ai_agents").values({ id: newId(), org_id: orgId, name: "Release bot", owner_user_id: kimId, client_id: `ag_${newId()}` }).execute();
  });
  sam = await enrolled("sams-mac", samId);
  await checkin(sam, healthy, { tools: [], mcp_servers: [] });
  await evaluate(h.deps, orgId); // alerting follows the audit log from here
});
afterAll(() => h.close());

describe("risk scores", () => {
  it("explain every point", async () => {
    const root = (await people()).find((p) => p.factors.some((f: any) => f.key === "admin"));
    expect(root).toMatchObject({ score: 55, level: "high" });
    expect(root.factors.map((f: any) => [f.key, f.points])).toEqual([
      ["no_mfa", 25],
      ["admin", 15],
      ["admin_no_mfa", 15],
    ]);
    expect(await of(samId)).toMatchObject({ score: 25, level: "medium", devices: 1, factors: [{ key: "no_mfa", title: "No MFA" }] });
    const kim = await of(kimId);
    expect(kim).toMatchObject({ agents: 1, level: "medium" });
    expect(kim.factors.find((f: any) => f.key === "agent_destructive")).toMatchObject({ points: 15, detail: "Release bot may use delete_repo" });
  });

  it("add up what's on someone's devices", async () => {
    await tenant((tx) => recomputeRisk(tx, orgId)); // baseline: no alerts
    expect((await h.call("GET", "/v1/audit/events?type=user.risk_raised", { token: admin })).body.data).toEqual([]);

    const srv = (o: Record<string, unknown>) => ({ client: "Cursor", user: "sam", scope: "user", transport: "http", ...o });
    await checkin(sam, { ...healthy, firewall: { status: "off" } }, {
      tools: [{ name: "Cursor", kind: "app" }],
      mcp_servers: [
        srv({ name: "gh", url: `${h.deps.cfg.apiPublicUrl}/mcp/${slug}/github` }),
        srv({ name: "gh-direct", client: "Claude Desktop", url: "https://api.githubcopilot.com/mcp/" }),
        srv({ name: "linear", url: "https://mcp.linear.app/sse", inline_secrets: true }),
      ],
    });
    const s = await of(samId);
    expect(s.factors.map((f: any) => f.key)).toEqual(["mcp_bypass", "no_mfa", "noncompliant", "mcp_secrets", "mcp_ungoverned"]);
    expect(s).toMatchObject({ score: 100, level: "critical", ai_clients: 2, mcp_servers: 3 });
    expect(s.factors.find((f: any) => f.key === "mcp_bypass").detail).toContain("gh-direct (Claude Desktop) on sams-mac");
    expect(s.factors.find((f: any) => f.key === "noncompliant").detail).toContain("firewall");
  });

  it("alert when someone rises to high or critical", async () => {
    const r = await tenant((tx) => recomputeRisk(tx, orgId));
    expect(r.raised).toEqual([samId]);
    const ev = (await h.call("GET", "/v1/audit/events?type=user.risk_raised", { token: admin })).body.data;
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ target: { id: samId }, details: { from: "medium", to: "critical", score: 100 } });
    await evaluate(h.deps, orgId);
    const alerts = (await h.call("GET", "/v1/alerts?status=all", { token: admin })).body.data;
    expect(alerts.find((a: any) => a.title.includes("risk became high"))).toBeTruthy();
    // Unchanged on the next run: no repeat.
    expect((await tenant((tx) => recomputeRisk(tx, orgId))).raised).toEqual([]);
  });
});

describe("the access graph", () => {
  it("links the person to devices, AI clients, MCP servers and the gateway's tools", async () => {
    const g = (await h.call("GET", `/v1/risk/people/${samId}/graph`, { token: admin })).body;
    const node = (id: string) => g.nodes.find((n: any) => n.id === id);
    const edge = (from: string, to: string) => g.edges.find((e: any) => e.from === from && e.to === to);
    expect(g.person).toMatchObject({ user_id: samId, level: "critical" });
    expect(node(`user:${samId}`)).toMatchObject({ type: "person", column: 0, label: "Sam Lee" });
    const dev = g.nodes.find((n: any) => n.type === "device");
    expect(dev).toMatchObject({ label: "sams-mac", tone: "danger" });
    expect(g.nodes.filter((n: any) => n.type === "client").map((n: any) => n.label).sort()).toEqual(["Claude Desktop", "Cursor"]);
    const servers = g.nodes.filter((n: any) => n.type === "server");
    expect(servers.map((s: any) => s.sublabel).sort()).toEqual(["bypasses gateway", "ungoverned · token in config", "via Nexus"]);
    const direct = servers.find((s: any) => s.sublabel === "bypasses gateway");
    expect(edge(direct.id, `nexus:${githubId}`)).toMatchObject({ label: "should go through", dashed: true, tone: "danger" });
    const via = servers.find((s: any) => s.sublabel === "via Nexus");
    expect(edge(via.id, `nexus:${githubId}`)).toMatchObject({ label: "policy + audit", tone: "success" });
    expect(node(`tools:${githubId}`)).toMatchObject({ label: "2 tools", sublabel: "1 destructive, 1 read", tone: "danger" });
  });

  it("shows the agents a person owns and what they may use", async () => {
    const g = (await h.call("GET", `/v1/risk/people/${kimId}/graph`, { token: admin })).body;
    const agent = g.nodes.find((n: any) => n.type === "agent");
    expect(agent).toMatchObject({ label: "Release bot", column: 2 });
    expect(g.edges.find((e: any) => e.from === agent.id)).toMatchObject({ to: `nexus:${githubId}`, label: "may use 1 destructive, 1 read", tone: "danger" });
  });

  it("needs org-wide user and device read access", async () => {
    const email = uniqueEmail("helpdesk");
    await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: "H", password: PASSWORD, roles: ["helpdesk"] } });
    const hd = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    expect((await h.call("GET", "/v1/risk/people", { token: hd })).status).toBe(200); // helpdesk reads users and devices org-wide
    expect((await h.call("GET", `/v1/risk/people/00000000-0000-4000-8000-000000000000/graph`, { token: admin })).status).toBe(404);
  });
});

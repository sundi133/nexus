import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Config as code (OPS-07, INT-05): export, plan and apply, staging to production. */

let h: Awaited<ReturnType<typeof bootApp>>;
type Org = { token: string; orgId: string; email: string };
let staging: Org;
let prod: Org;

async function org(name: string): Promise<Org> {
  const email = uniqueEmail(name.toLowerCase().replace(/\W/g, ""));
  const token = (await h.call("POST", "/v1/signup", { body: { organization_name: name, email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  const orgId = (await h.call("GET", "/v1/me", { token })).body.organization.id;
  // Apps are connected by hand in each environment; config refers to them by name.
  await h.call("POST", "/v1/apps", { token, body: { protocol: "oidc", name: "Payroll", redirect_uris: ["https://payroll.example.com/cb"] } });
  return { token, orgId, email };
}
const plan = (o: Org, config: unknown, prune = false) => h.call("POST", "/v1/config/plan", { token: o.token, body: { config, prune } });
const apply = (o: Org, config: unknown, extra: Record<string, unknown> = {}) => h.call("POST", "/v1/config/apply", { token: o.token, body: { config, ...extra } });
const exportOf = async (o: Org) => (await h.call("GET", "/v1/config", { token: o.token })).body;

beforeAll(async () => {
  h = await bootApp();
  staging = await org("Staging Co");
  prod = await org("Prod Co");
  // Build staging by hand, through the normal API.
  const t = staging.token;
  const eng = (await h.call("POST", "/v1/groups", { token: t, body: { name: "Engineering", rule: { match: "all", conditions: [{ attribute: "department", op: "equals", value: "engineering" }] } } })).body.id;
  await h.call("POST", "/v1/groups", { token: t, body: { name: "Contractors", description: "External" } });
  const payroll = (await h.call("GET", "/v1/apps", { token: t })).body.data[0].id;
  await h.call("POST", "/v1/access-policies", { token: t, body: { name: "MFA for payroll", requirement: "require_mfa", mode: "enforce", conditions: { apps: [payroll], users: { include: { groups: [eng], users: [] } } } } });
  await h.call("PUT", "/v1/device-policies/screen_lock", { token: t, body: { enabled: true, params: { max_delay_minutes: 5 }, mode: "audit", grace_hours: 48 } });
  await h.call("POST", "/v1/alert-rules", { token: t, body: { name: "Agents created", severity: "low", match: { types: ["agent.registered"] } } });
  const me = (await h.call("GET", "/v1/me", { token: t })).body.user.id;
  await h.call("POST", "/v1/agents", { token: t, body: { name: "Triage bot", owner_user_id: me, tags: ["support"], risk_tier: "high" } });
  await h.call("POST", "/v1/mcp/servers", { token: t, body: { name: "Docs", slug: "docs", url: "http://127.0.0.1:9/mcp" } });
  const srv = (await h.call("GET", "/v1/mcp/servers", { token: t })).body.data[0].id;
  // No tools were discovered (nothing listens there): permissions can still name every tool.
  await h.call("POST", `/v1/mcp/servers/${srv}/permissions`, { token: t, body: { effect: "allow", subject: { type: "agent_tag", tag: "support" }, tools: ["*"], risks: ["read"] } });
});
afterAll(async () => {
  await h.close();
});

describe("export", () => {
  it("describes the organization by name, without secrets or IDs", async () => {
    const doc = await exportOf(staging);
    expect(doc.version).toBe(1);
    expect(doc.groups.map((g: any) => g.name).sort()).toEqual(["Contractors", "Engineering"]);
    expect(doc.conditional_access[0]).toMatchObject({ name: "MFA for payroll", apps: ["Payroll"], users: { include: { groups: ["Engineering"], users: [] } } });
    expect(doc.device_policies.find((d: any) => d.check === "screen_lock")).toMatchObject({ mode: "audit", grace_hours: 48, params: { max_delay_minutes: 5 } });
    expect(doc.agents[0]).toMatchObject({ name: "Triage bot", owner: staging.email, tags: ["support"] });
    expect(doc.mcp_servers[0]).toMatchObject({ slug: "docs", auth: { kind: "none" }, permissions: [{ subject: "tag:support", tools: ["*"], risks: ["read"] }] });
    expect(doc.alert_rules.find((r: any) => r.builtin === "failed_logins")).toBeTruthy();
    expect(JSON.stringify(doc)).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-/); // no IDs
  });
});

describe("staging to production", () => {
  let doc: any;
  it("plans the whole difference, and applies it in one go", async () => {
    doc = await exportOf(staging);
    doc.agents[0].owner = prod.email; // people differ between environments
    const p = await plan(prod, doc);
    expect(p.status, JSON.stringify(p.body)).toBe(200);
    const creates = p.body.changes.filter((c: any) => c.action === "create").map((c: any) => `${c.section}:${c.key}`);
    expect(creates).toEqual(expect.arrayContaining(["groups:Engineering", "groups:Contractors", "conditional_access:MFA for payroll", "alert_rules:Agents created", "agents:Triage bot", "mcp_servers:docs"]));
    expect(await exportOf(prod).then((d) => d.groups)).toEqual([]); // planning changed nothing

    const a = await apply(prod, doc, { plan_id: p.body.plan_id });
    expect(a.status, JSON.stringify(a.body)).toBe(200);
    const after = await exportOf(prod);
    const strip = (d: any) => ({ ...d, agents: d.agents.map((x: any) => ({ ...x, owner: "" })) });
    expect(strip(after)).toEqual(strip(doc));
    const ev = (await h.call("GET", "/v1/audit/events?type=config.applied", { token: prod.token })).body.data[0];
    expect(ev.details).toMatchObject({ plan_id: p.body.plan_id, prune: false });
    expect((await h.call("GET", "/v1/audit/events?type=group.created", { token: prod.token })).body.data[0].details.via).toBe("config");
  });

  it("is idempotent: a second plan has nothing to do", async () => {
    const p = await plan(prod, doc);
    expect(p.body.changes, JSON.stringify(p.body.changes)).toEqual([]);
  });

  it("only deletes with prune", async () => {
    const smaller = { version: 1, groups: doc.groups.filter((g: any) => g.name !== "Contractors") };
    expect((await plan(prod, smaller)).body.changes).toEqual([]);
    const p = await plan(prod, smaller, true);
    expect(p.body.changes).toEqual([{ section: "groups", action: "delete", key: "Contractors" }]);
    await apply(prod, smaller, { prune: true });
    expect((await exportOf(prod)).groups.map((g: any) => g.name)).toEqual(["Engineering"]);
  });

  it("refuses a stale plan", async () => {
    const changed = { version: 1, alert_rules: [{ name: "Agents created", severity: "medium", match: { types: ["agent.registered"] } }] };
    const p = await plan(prod, changed);
    await h.call("POST", "/v1/alert-rules", { token: prod.token, body: { name: "Meanwhile", severity: "low", match: { types: ["x.y"] } } });
    const other = { version: 1, alert_rules: [...changed.alert_rules, { name: "Meanwhile", severity: "high", match: { types: ["x.y"] } }] };
    expect((await apply(prod, other, { plan_id: p.body.plan_id })).body.code).toBe("plan_changed");
  });
});

describe("safety", () => {
  it("rejects unknown references, all or nothing", async () => {
    const bad = {
      version: 1,
      groups: [{ name: "New team" }],
      conditional_access: [{ name: "Block wiki", requirement: "block", apps: ["Wiki"], users: { include: { groups: ["Ghosts"], users: ["nobody@example.com"] } } }],
    };
    const r = await apply(prod, bad);
    expect(r.status).toBe(400);
    expect(r.body.problems).toEqual(['conditional_access "Block wiki": unknown app "Wiki"', 'conditional_access "Block wiki": unknown group "Ghosts"', 'conditional_access "Block wiki": unknown person "nobody@example.com"']);
    expect((await exportOf(prod)).groups.map((g: any) => g.name)).not.toContain("New team");
  });

  it("needs a token for a new authenticated MCP server, which it never exports", async () => {
    const d = { version: 1, mcp_servers: [{ slug: "gh", name: "GitHub", url: "https://gh.example.com/mcp", auth: { kind: "bearer", token_env: "GH_TOKEN" } }] };
    expect((await plan(prod, d)).body.problems).toEqual(['mcp_servers "gh": auth needs a token (set GH_TOKEN for the CLI)']);
    const ok = await apply(prod, { ...d, mcp_servers: [{ ...d.mcp_servers[0], auth: { kind: "bearer", token: "ghp_supersecret" } }] });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    const out = JSON.stringify(await exportOf(prod));
    expect(out).not.toContain("ghp_supersecret");
    expect(out).toContain("NEXUS_MCP_GH_TOKEN");
    // Re-applying the exported doc (no token) keeps the stored secret.
    expect((await plan(prod, { version: 1, mcp_servers: (await exportOf(prod)).mcp_servers })).body.changes).toEqual([]);
  });

  it("checks each section's permission", async () => {
    const email = uniqueEmail("helper");
    await h.call("POST", "/v1/users", { token: prod.token, body: { email, given_name: "H", password: PASSWORD, roles: ["helpdesk"] } });
    const t = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    expect((await h.call("POST", "/v1/config/plan", { token: t, body: { config: { version: 1, groups: [] } } })).status).toBe(403);
  });
});

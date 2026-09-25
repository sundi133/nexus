import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Compliance reports (AUD-06). */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let token = "";
let orgId = "";
const P: Record<string, { id: string; email: string }> = {};

const report = (kind: string, q = "") => h.call("GET", `/v1/reports/${kind}${q}`, { token }).then((r) => r.body);

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("root");
  token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Report Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token })).body;
  orgId = me.organization.id;
  P.root = { id: me.user.id, email };
  for (const [n, extra] of [["ann", { roles: ["helpdesk"] }], ["bo", {}], ["cy", { given_name: "=cmd|' /C calc'!A0" }]] as const) {
    const e = uniqueEmail(n);
    P[n] = { id: (await h.call("POST", "/v1/users", { token, body: { email: e, given_name: n, password: PASSWORD, ...extra } })).body.id, email: e };
  }
  // A verified authenticator for Ann (enrollment itself is covered by the MFA tests).
  await owner.query("INSERT INTO auth_factors (id, org_id, user_id, type, name, secret_sealed, verified_at) VALUES (gen_random_uuid(), $1, $2, 'totp', 'Phone', '\\x00', now())", [orgId, P.ann!.id]);
  await owner.query("UPDATE users SET last_login_at = now() - interval '200 days', created_at = now() - interval '300 days' WHERE id = $1", [P.bo!.id]);
  const app = (await h.call("POST", "/v1/apps", { token, body: { protocol: "oidc", name: "Wiki", redirect_uris: ["https://wiki.example.com/cb"] } })).body.app.id;
  const g = (await h.call("POST", "/v1/groups", { token, body: { name: "Staff" } })).body.id;
  await h.call("POST", `/v1/groups/${g}/members`, { token, body: { user_ids: [P.bo!.id, P.cy!.id] } });
  await h.call("POST", `/v1/apps/${app}/assignments`, { token, body: { principals: [{ type: "user", id: P.ann!.id }, { type: "group", id: g }] } });
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("reports", () => {
  it("lists what's available", async () => {
    const kinds = (await h.call("GET", "/v1/reports", { token })).body.data.map((r: any) => r.kind);
    expect(kinds).toEqual(["mfa_coverage", "admin_access", "dormant_accounts", "device_compliance", "app_access", "agent_tool_access"]);
  });

  it("MFA coverage counts people with a verified factor", async () => {
    const r = await report("mfa_coverage");
    expect(r.summary).toMatchObject({ people: 4, with_mfa: 1, without_mfa: 3, coverage_percent: 25 });
    expect(r.rows.find((x: any) => x[1] === P.ann!.email).slice(2, 5)).toEqual([true, false, "totp"]);
  });

  it("admin access lists every admin role holder", async () => {
    const r = await report("admin_access");
    expect(r.rows.map((x: any) => [x[1], x[2]])).toEqual(expect.arrayContaining([[P.root!.email, "owner"], [P.ann!.email, "helpdesk"]]));
    expect(r.summary).toMatchObject({ admins: 2, owners: 1 });
  });

  it("dormant accounts respect the day count", async () => {
    expect((await report("dormant_accounts")).rows.map((x: any) => x[1])).toEqual([P.bo!.email]);
    expect((await report("dormant_accounts", "?days=365")).rows).toEqual([]);
  });

  it("app access explains why each person has access", async () => {
    const r = await report("app_access");
    expect(r.rows.map((x: any) => [x[2], x[3]]).sort()).toEqual([[P.ann!.email, "direct"], [P.bo!.email, "group Staff"], [P.cy!.email, "group Staff"]].sort());
  });

  it("exports formula-safe CSV and audits every export", async () => {
    const res = await h.app.request("/v1/reports/app_access?format=csv", { headers: { authorization: `Bearer ${token}` } });
    expect(res.headers.get("content-type")).toContain("text/csv");
    const csv = await res.text();
    expect(csv.split("\r\n")[0]).toBe('"app","name","email","via","status"');
    expect(csv).toContain(`"'=cmd|' /C calc'!A0"`);
    const ev = (await h.call("GET", "/v1/audit/events?type=report.generated", { token })).body.data[0];
    expect(ev.details).toMatchObject({ report: "app_access", format: "csv", rows: 3 });
  });

  it("agent tool access shows what each agent can call", async () => {
    expect((await report("agent_tool_access")).summary).toMatchObject({ agents: 0, grants: 0 });
    const agent = (await h.call("POST", "/v1/agents", { token, body: { name: "Bot", owner_user_id: P.root!.id, tags: ["ops"] } })).body.id;
    const srv = "00000000-0000-7000-8000-00000000aa01";
    await owner.query("INSERT INTO mcp_servers (id, org_id, name, slug, url) VALUES ($1, $2, 'GitHub', 'github', 'https://gh.example.com/mcp')", [srv, orgId]);
    const tool = (name: string, risk: string, status = "approved") =>
      owner.query("INSERT INTO mcp_tools (id, org_id, server_id, name, hash, approved_hash, status, change, risk) VALUES (gen_random_uuid(), $1, $2, $3, 'h', 'h', $4, '', $5)", [orgId, srv, name, status, risk]);
    await tool("list_issues", "read");
    await tool("delete_repo", "destructive");
    await tool("create_issue", "write", "pending");
    await owner.query("INSERT INTO mcp_permissions (id, org_id, server_id, effect, subject_type, subject_tag, tools, conditions) VALUES (gen_random_uuid(), $1, $2, 'allow', 'agent_tag', 'ops', '{*}', $3)", [orgId, srv, JSON.stringify([{ argument: "repo", op: "in", values: ["a/b"] }])]);
    const r = await report("agent_tool_access");
    expect(r.rows.map((x: any) => [x[0], x[5], x[6], x[7]]).sort()).toEqual([["Bot", "delete_repo", "destructive", "with argument conditions"], ["Bot", "list_issues", "read", "with argument conditions"]]); // not the unapproved tool
    expect(r.summary).toMatchObject({ agents: 1, grants: 2, destructive_grants: 1 });
    expect(agent).toBeTruthy();
  });

  it("is for admins who can read the audit log", async () => {
    const t = (await h.call("POST", "/v1/auth/login", { body: { email: P.bo!.email, password: PASSWORD } })).body.token;
    expect((await h.call("GET", "/v1/reports/mfa_coverage", { token: t })).status).toBe(403);
  });
});

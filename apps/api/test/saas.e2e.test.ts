import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SAAS_APPS } from "../src/saas/catalog.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** SaaS management: discovery from browsers (only when on), review decisions, and browser enforcement. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let viewer = "";
let token = "";
let alice = "";
let bob = "";
let orgId = "";

const sync = async (user: string, events: unknown[], policyVersion = "") => {
  const res = await h.app.request("/v1/browser/extension/sync", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `NexusBrowser ${token}` },
    body: JSON.stringify({ user, extension_version: "0.2.0", policy_version: policyVersion, events }),
  });
  return (await res.json()) as { version: string; policy: any; accepted: number };
};
const now = () => new Date().toISOString();
const ev = (kind: string, app: string, count = 1, extra: Record<string, unknown> = {}) => ({ at: now(), kind, action: "allowed", app, host: "", count, ...extra });
const apps = async (q = "") => (await h.call("GET", `/v1/saas/apps${q}`, { token: admin })).body;

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "SaaS Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  alice = uniqueEmail("alice");
  bob = uniqueEmail("bob");
  await h.call("POST", "/v1/users", { token: admin, body: { email: alice, given_name: "Alice", password: PASSWORD } });
  const v = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: v, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  viewer = (await h.call("POST", "/v1/auth/login", { body: { email: v, password: PASSWORD } })).body.token;
  token = (await h.call("POST", "/v1/browser/tokens", { token: admin, body: { name: "All browsers" } })).body.token;
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("SaaS management", () => {
  it("recognises 1,000+ apps, each host belonging to one app", async () => {
    expect(SAAS_APPS.length).toBeGreaterThan(1000);
    const hosts = SAAS_APPS.flatMap((a) => a.hosts);
    expect(new Set(hosts).size).toBe(hosts.length);
    expect(new Set(SAAS_APPS.map((a) => a.key)).size).toBe(SAAS_APPS.length);
    const found = (await h.call("GET", "/v1/saas/catalog?q=salesforce", { token: admin })).body;
    expect(found.data.map((a: any) => a.key)).toContain("salesforce");
    expect(found.total).toBe(SAAS_APPS.length);
  });

  it("counts nothing until discovery is turned on", async () => {
    const off = await sync(alice, [ev("saas", "slack", 3)]);
    expect(off.policy.saas).toEqual({ discovery: false, apps: [] });
    expect((await db.query("SELECT count(*)::int AS n FROM saas_usage WHERE org_id = $1", [orgId])).rows[0].n).toBe(0);

    const cur = (await h.call("GET", "/v1/browser/policy", { token: admin })).body;
    const put = await h.call("PUT", "/v1/browser/policy", { token: admin, body: { apps: {}, dlp: { detectors: cur.dlp.detectors, custom: [] }, uploads: "allow", message: "", saas_discovery: true } });
    expect(put.body.saas_discovery).toBe(true);
    const on = await sync(alice, [], off.version);
    expect(on.policy.saas.discovery).toBe(true);
    expect(on.policy.saas.apps.length).toBe(SAAS_APPS.length);
    // Saving the AI settings without mentioning discovery leaves it on.
    await h.call("PUT", "/v1/browser/policy", { token: admin, body: { apps: {}, dlp: { detectors: cur.dlp.detectors, custom: [] }, uploads: "warn", message: "" } });
    expect((await h.call("GET", "/v1/browser/policy", { token: admin })).body.saas_discovery).toBe(true);
  });

  it("adds up visits and password sign-ins per person per day", async () => {
    const old = new Date(Date.now() - 30 * 86_400_000).toISOString();
    await sync(alice, [ev("saas", "slack", 3), ev("saas_login", "slack"), ev("saas", "not-an-app"), { ...ev("saas", "notion"), at: old }]);
    await sync(alice, [ev("saas", "slack", 2)]);
    await sync(bob, [ev("saas", "slack"), ev("saas", "zoom", 4), ev("saas_login", "zoom")]);
    const r = await apps();
    const slack = r.data.find((a: any) => a.key === "slack");
    expect(slack).toMatchObject({ name: "Slack", category: "Collaboration", people: 2, visits: 6, password_logins: 1, password_people: 1, status: "unreviewed", sso: null });
    expect(r.data.map((a: any) => a.key)).not.toContain("notion"); // too old to be trusted
    expect(r.summary).toMatchObject({ discovery: true, apps: 2, people: 2, unreviewed: 2, unapproved_in_use: 0 });
    const rows = (await db.query("SELECT app_key, user_email, visits FROM saas_usage WHERE org_id = $1 ORDER BY app_key, user_email", [orgId])).rows;
    expect(rows).toHaveLength(3); // one row per app, person and day
    expect(JSON.stringify(rows)).not.toMatch(/https?:/);

    const one = (await h.call("GET", "/v1/saas/apps/slack", { token: viewer })).body;
    expect(one.people.map((p: any) => [p.email, p.visits, p.password_logins])).toEqual(expect.arrayContaining([[alice, 5, 1], [bob, 1, 0]]));
    expect(one.people.find((p: any) => p.email === alice).user_id).toBeTruthy();
  });

  it("shows which apps are on SSO yet still get password sign-ins", async () => {
    await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "oidc", name: "Zoom", redirect_uris: ["https://zoom.example.com/cb"] } });
    const r = await apps();
    expect(r.data.find((a: any) => a.key === "zoom").sso).toMatchObject({ name: "Zoom" });
    expect(r.summary.password_apps).toBe(1);
  });

  it("approves, or marks unapproved and has browsers warn or block", async () => {
    const put = (key: string, body: unknown, t = admin) => h.call("PUT", `/v1/saas/apps/${key}`, { token: t, body });
    expect((await put("slack", { status: "approved" }, viewer)).status).toBe(403);
    expect((await put("slack", { status: "approved", action: "block" })).body.code).toBe("action_needs_unapproved");
    expect((await put("slack", { status: "approved", notes: "Company workspace" })).body).toMatchObject({ status: "approved", action: "allow", notes: "Company workspace" });
    expect((await put("dropbox", { status: "unapproved", action: "block" })).body).toMatchObject({ status: "unapproved", action: "block", people: 0 });

    const p = (await sync(alice, [])).policy;
    expect(p.apps.find((a: any) => a.key === "dropbox")).toMatchObject({ kind: "saas", action: "block", hosts: expect.arrayContaining(["dropbox.com"]) });
    expect(p.apps.find((a: any) => a.key === "slack")).toBeUndefined(); // approved: nothing to enforce

    await sync(alice, [{ at: now(), kind: "visit", action: "blocked", app: "dropbox", host: "www.dropbox.com" }]);
    const r = await apps("?status=unapproved");
    expect(r.data.map((a: any) => [a.key, a.blocked])).toEqual([["dropbox", 1]]);
    expect((await db.query("SELECT count(*)::int AS n FROM browser_events WHERE org_id = $1 AND (app = 'dropbox' OR host LIKE '%dropbox%')", [orgId])).rows[0].n).toBe(0); // counted, not logged

    expect((await put("dropbox", { status: "unreviewed" })).body.status).toBe("unreviewed");
    expect((await sync(alice, [])).policy.apps.find((a: any) => a.key === "dropbox")).toBeUndefined();
    const audits = (await db.query("SELECT details FROM audit_events WHERE org_id = $1 AND type = 'saas.app_reviewed' ORDER BY ts, id", [orgId])).rows.map((r: any) => `${r.details.app}:${r.details.to.status}`);
    expect(audits).toEqual(["slack:approved", "dropbox:unapproved", "dropbox:unreviewed"]);
  });
});

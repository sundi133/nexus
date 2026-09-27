import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** AI apps in the browser: the extension's policy, its reports, and what admins see. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let helpdesk = "";
let orgId = "";
let token = "";
let tokenId = "";
const pat = uniqueEmail("pat");

const sync = async (body: unknown, auth = `NexusBrowser ${token}`) => {
  const res = await h.app.request("/v1/browser/extension/sync", { method: "POST", headers: { "content-type": "application/json", authorization: auth }, body: JSON.stringify(body) });
  return { status: res.status, body: (await res.json()) as any };
};
const now = () => new Date().toISOString();

beforeAll(async () => {
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Browser Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  await h.call("POST", "/v1/users", { token: admin, body: { email: pat, given_name: "Pat", password: PASSWORD } });
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("policy", () => {
  it("starts with every app allowed and secrets blocked", async () => {
    const p = (await h.call("GET", "/v1/browser/policy", { token: admin })).body;
    expect(p.apps.find((a: any) => a.key === "chatgpt")).toMatchObject({ name: "ChatGPT", hosts: ["chatgpt.com", "chat.openai.com"], action: "allow" });
    expect(p.dlp.detectors).toMatchObject({ secret: "block", private_key: "block", credit_card: "warn", us_ssn: "warn", iban: "monitor", email_list: "monitor" });
    expect(p.uploads).toBe("allow");
  });

  it("refuses unknown apps and patterns that could freeze a browser", async () => {
    const put = (body: unknown, t = admin) => h.call("PUT", "/v1/browser/policy", { token: t, body });
    expect((await put({ apps: { chatgpt: "block" } }, helpdesk)).status).toBe(403);
    expect((await put({ apps: { notanapp: "block" } })).body.code).toBe("unknown_app");
    expect((await put({ dlp: { custom: [{ id: "x", name: "X", pattern: "([", action: "warn" }] } })).status).toBe(400);
    expect((await put({ dlp: { custom: [{ id: "x", name: "X", pattern: "(a+)+b", action: "warn" }] } })).status).toBe(400);
  });

  it("saves apps, detectors, custom patterns and uploads, and audits the change", async () => {
    const r = await h.call("PUT", "/v1/browser/policy", {
      token: admin,
      body: { apps: { deepseek: "block", character_ai: "warn" }, dlp: { detectors: { iban: "warn" }, custom: [{ id: "falcon", name: "Project Falcon", pattern: "project\\s+falcon", action: "block" }] }, uploads: "warn", message: "See go/ai-policy" },
    });
    expect(r.status).toBe(200);
    expect(r.body.apps.find((a: any) => a.key === "deepseek").action).toBe("block");
    expect(r.body.dlp.detectors).toMatchObject({ iban: "warn", secret: "block" }); // unset detectors keep their defaults
    expect((await db.query("SELECT 1 FROM audit_events WHERE org_id = $1 AND type = 'browser.policy_updated'", [orgId])).rowCount).toBe(1);
  });
});

describe("the extension", () => {
  it("needs a live organization token", async () => {
    const t = await h.call("POST", "/v1/browser/tokens", { token: admin, body: { name: "Chrome, all staff" } });
    expect(t.status).toBe(201);
    expect(t.body.token).toMatch(/^nxb_/);
    token = t.body.token;
    tokenId = t.body.id;
    expect((await h.call("GET", "/v1/browser/tokens", { token: admin })).body.data[0]).not.toHaveProperty("token");
    expect((await sync({}, "")).status).toBe(401);
    expect((await sync({}, "NexusBrowser nxb_forged")).status).toBe(401);
  });

  it("gets the policy, and only again when it changes", async () => {
    const first = await sync({ user: pat, extension_version: "0.1.0" });
    expect(first.status).toBe(200);
    expect(first.body.policy.apps.find((a: any) => a.key === "deepseek")).toMatchObject({ action: "block", hosts: ["chat.deepseek.com"] });
    expect(first.body.policy.dlp.custom[0]).toMatchObject({ id: "falcon", action: "block" });
    expect(first.body.policy.message).toBe("See go/ai-policy");
    const again = await sync({ user: pat, policy_version: first.body.version });
    expect(again.body).toMatchObject({ version: first.body.version, policy: null });
  });

  it("reports what happened, matched to the person, with security events audited", async () => {
    const r = await sync({
      user: pat.toUpperCase(),
      extension_version: "0.1.0",
      events: [
        { at: now(), kind: "visit", action: "allowed", app: "chatgpt", host: "chatgpt.com", count: 7 },
        { at: now(), kind: "visit", action: "blocked", app: "deepseek", host: "chat.deepseek.com" },
        { at: now(), kind: "dlp", action: "blocked", app: "chatgpt", host: "chatgpt.com", detector: "secret", detail: "AWS access key AKIA…LE" },
        { at: now(), kind: "dlp", action: "continued", app: "claude", host: "claude.ai", detector: "credit_card", detail: "•••• 4242" },
      ],
    });
    expect(r.body.accepted).toBe(4);
    // A malformed event is skipped, not a reason to refuse the batch (the browser would resend it forever).
    const mixed = await sync({ user: pat, events: [{ kind: "upload", action: "blocked", count: 0 }, { at: now(), kind: "visit", action: "allowed", app: "gemini", host: "gemini.google.com" }] });
    expect(mixed.body.accepted).toBe(1);
    const rows = (await db.query("SELECT user_id, kind, action, app FROM browser_events WHERE org_id = $1 ORDER BY kind, action", [orgId])).rows;
    const patId = (await db.query("SELECT id FROM users WHERE email = $1", [pat])).rows[0].id;
    expect(rows.every((x) => x.user_id === patId)).toBe(true);
    const audited = (await db.query("SELECT type, actor_display FROM audit_events WHERE org_id = $1 AND type LIKE 'browser.dlp%' ORDER BY type", [orgId])).rows;
    expect(audited).toEqual([
      { type: "browser.dlp_blocked", actor_display: pat },
      { type: "browser.dlp_continued", actor_display: pat },
    ]);

    const usage = (await h.call("GET", "/v1/browser/usage", { token: helpdesk })).body;
    expect(usage.data.find((x: any) => x.app === "chatgpt")).toMatchObject({ people: 1, visits: 7, sensitive: 1, blocked: 1 });
    expect(usage.browsers.people).toBe(1);
    const dlp = (await h.call("GET", "/v1/browser/events?kind=dlp", { token: admin })).body.data;
    expect(dlp.map((e: any) => [e.app_name, e.action])).toEqual(expect.arrayContaining([["ChatGPT", "blocked"], ["Claude", "continued"]]));
  });

  it("stops working when its token is revoked", async () => {
    expect((await h.call("DELETE", `/v1/browser/tokens/${tokenId}`, { token: admin })).status).toBe(204);
    expect((await sync({})).status).toBe(401);
  });
});

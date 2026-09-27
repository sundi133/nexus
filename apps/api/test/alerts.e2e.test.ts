import http from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { evaluate } from "../src/alerts/engine.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Alerting, triage and on-call paging (AUD-08, OPS-08, NTF-09, NTF-10). */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let token = "";
let orgId = "";
let victim = { id: "", email: "" };

// Fake PagerDuty Events API and Opsgenie Alerts API.
const received: { service: "pagerduty" | "opsgenie"; path: string; auth: string; body: any }[] = [];
let fake: http.Server;
let base = "";

const alerts = (q = "") => h.call("GET", `/v1/alerts${q}`, { token }).then((r) => r.body);
const act = (id: string, body: Record<string, unknown>, t = token) => h.call("POST", `/v1/alerts/${id}/actions`, { token: t, body });
const run = async () => {
  await evaluate(h.deps, orgId);
  await h.jobs.runOnce({ orgId });
};
const hook = (url: string, body: unknown) => h.app.request(new URL(url).pathname, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
const failLogin = () => h.call("POST", "/v1/auth/login", { body: { email: victim.email, password: "wrong-password-123" } });

beforeAll(async () => {
  fake = http.createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => {
      received.push({ service: req.url!.startsWith("/pd") ? "pagerduty" : "opsgenie", path: req.url!, auth: String(req.headers.authorization ?? ""), body: b ? JSON.parse(b) : null });
      res.writeHead(202, { "content-type": "application/json" }).end('{"status":"success"}');
    });
  });
  await new Promise<void>((r) => fake.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(fake.address() as AddressInfo).port}`;
  h = await bootApp({ pagerdutyEventsUrl: `${base}/pd/v2/enqueue`, opsgenieBase: { us: `${base}/og`, eu: `${base}/og-eu` } });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("root");
  token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Alert Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token })).body.organization.id;
  victim.email = uniqueEmail("victim");
  victim.id = (await h.call("POST", "/v1/users", { token, body: { email: victim.email, given_name: "Vic", password: PASSWORD } })).body.id;
  await run(); // starts the cursor: history isn't alerted on
});
afterAll(async () => {
  fake.close();
  await owner.end();
  await h.close();
});

describe("rules and deduplication", () => {
  it("starts every organization with sensible default rules", async () => {
    const rules = (await h.call("GET", "/v1/alert-rules", { token })).body.data;
    expect(rules.length).toBeGreaterThanOrEqual(10);
    expect(rules.find((r: any) => r.name === "Repeated failed sign-ins")).toMatchObject({ builtin: true, severity: "high", threshold: 8, group_by: "actor" });
  });

  it("fires once when the threshold is reached, then folds further matches in", async () => {
    for (let i = 0; i < 7; i++) await failLogin();
    await run();
    expect((await alerts()).data).toHaveLength(0);
    await failLogin();
    await run();
    const list = (await alerts()).data;
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ title: `Repeated failed sign-ins: ${victim.email}`, severity: "high", status: "open", count: 8 });
    await failLogin();
    await failLogin();
    await run();
    const again = (await alerts()).data;
    expect(again).toHaveLength(1);
    expect(again[0].count).toBe(10);
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=10&filter=all", { token })).body.data.filter((n: any) => n.title.startsWith("Repeated failed"));
    expect(inbox).toHaveLength(1); // told once
    const detail = (await h.call("GET", `/v1/alerts/${again[0].id}`, { token })).body;
    expect(detail.events).toHaveLength(10);
    expect(detail.events.every((e: any) => e.type === "auth.login" && e.outcome === "failure")).toBe(true);
  });

  it("validates custom rules, and keeps defaults from being deleted", async () => {
    expect((await h.call("POST", "/v1/alert-rules", { token, body: { name: "x", severity: "low", match: { types: ["DROP TABLE"] } } })).status).toBe(400);
    const rules = (await h.call("GET", "/v1/alert-rules", { token })).body.data;
    const builtin = rules.find((r: any) => r.builtin);
    expect((await h.call("DELETE", `/v1/alert-rules/${builtin.id}`, { token })).body.code).toBe("builtin");
    const off = await h.call("PATCH", `/v1/alert-rules/${builtin.id}`, { token, body: { enabled: false } });
    expect(off.body.data.find((r: any) => r.id === builtin.id).enabled).toBe(false);
  });
});

describe("on-call paging", () => {
  let pdHook = "";
  let ogHook = "";
  let alertId = "";

  it("pages PagerDuty for alerts at its minimum severity, keyed by the alert", async () => {
    const pd = await h.call("POST", "/v1/oncall-integrations", { token, body: { kind: "pagerduty", name: "PagerDuty SecOps", key: "pd-routing-key-123", min_severity: "high" } });
    expect(pd.status, JSON.stringify(pd.body)).toBe(201);
    pdHook = pd.body.webhook_url;
    expect(pdHook).toMatch(/\/hooks\/oncall\/nxoc_/);
    const og = await h.call("POST", "/v1/oncall-integrations", { token, body: { kind: "opsgenie", name: "Opsgenie", key: "og-api-key-456", min_severity: "critical" } });
    ogHook = og.body.webhook_url;
    await h.call("POST", "/v1/alert-rules", { token, body: { name: "Group made", severity: "high", match: { types: ["group.created"] } } });
    received.length = 0;
    await h.call("POST", "/v1/groups", { token, body: { name: "Suspicious" } });
    await run();
    alertId = (await alerts()).data.find((a: any) => a.title.startsWith("Group made")).id;
    expect(received).toHaveLength(1); // high: PagerDuty only
    expect(received[0]).toMatchObject({ service: "pagerduty", body: { routing_key: "pd-routing-key-123", event_action: "trigger", dedup_key: alertId, payload: { severity: "error", source: "Votal Nexus" } } });
  });

  it("acknowledging in Nexus acknowledges in PagerDuty", async () => {
    received.length = 0;
    const r = await act(alertId, { action: "acknowledge" });
    expect(r.body.alert).toMatchObject({ status: "acknowledged", acknowledged_by: expect.stringContaining("root") });
    await h.jobs.runOnce({ orgId });
    expect(received.map((x) => x.body.event_action)).toEqual(["acknowledge"]);
  });

  it("resolving in PagerDuty resolves in Nexus, without echoing back", async () => {
    received.length = 0;
    const res = await hook(pdHook, { event: { event_type: "incident.resolved", agent: { summary: "Dana On-call" }, data: { id: "Q1", incident_key: alertId, title: "Group made" } } });
    expect(await res.json()).toMatchObject({ ok: true, updated: true });
    const a = (await h.call("GET", `/v1/alerts/${alertId}`, { token })).body.alert;
    expect(a).toMatchObject({ status: "resolved", resolved_by: "PagerDuty SecOps (Dana On-call)" });
    await h.jobs.runOnce({ orgId });
    expect(received).toHaveLength(0);
    expect((await hook(`${pdHook}x`, {})).status).toBe(404); // wrong token
  });

  it("pages Opsgenie for critical alerts and takes its acknowledgements", async () => {
    await h.call("POST", "/v1/alert-rules", { token, body: { name: "Break glass drill", severity: "critical", match: { types: ["group.deleted"] } } });
    const g = (await h.call("POST", "/v1/groups", { token, body: { name: "Drill" } })).body.id;
    received.length = 0;
    await h.call("DELETE", `/v1/groups/${g}`, { token });
    await run();
    const a = (await alerts()).data.find((x: any) => x.title.startsWith("Break glass drill"));
    const forThis = received.filter((x) => x.body?.dedup_key === a.id || x.body?.alias === a.id);
    expect(forThis.map((x) => x.service).sort()).toEqual(["opsgenie", "pagerduty"]); // critical: both
    const og = received.find((x) => x.service === "opsgenie")!;
    expect(og).toMatchObject({ path: "/og/v2/alerts", auth: "GenieKey og-api-key-456", body: { alias: a.id, priority: "P1" } });
    received.length = 0;
    await hook(ogHook, { action: "Acknowledge", alert: { alias: a.id, username: "sam@example.com" } });
    expect((await h.call("GET", `/v1/alerts/${a.id}`, { token })).body.alert).toMatchObject({ status: "acknowledged", acknowledged_by: "Opsgenie (sam@example.com)" });
    await h.jobs.runOnce({ orgId });
    expect(received.map((x) => `${x.service}:${x.body.event_action ?? x.path}`)).toEqual(["pagerduty:acknowledge"]); // not back to Opsgenie
  });
});

describe("triage", () => {
  it("snoozes, assigns, notes, and resolves with a verdict that feeds rule quality", async () => {
    const a = (await alerts()).data.find((x: any) => x.title.startsWith("Repeated failed"));
    await act(a.id, { action: "snooze", minutes: 60 });
    const active = await alerts();
    expect(active.data.map((x: any) => x.id)).not.toContain(a.id);
    expect(active.counts.snoozed).toBe(1);
    await act(a.id, { action: "unsnooze" });
    const me = (await h.call("GET", "/v1/me", { token })).body.user.id;
    await act(a.id, { action: "assign", user_id: me });
    await act(a.id, { action: "note", body: "Vic mistyped after a password change" });
    const done = await act(a.id, { action: "resolve", resolution: "false_positive" });
    expect(done.body.alert).toMatchObject({ status: "resolved", resolution: "false_positive", assignee: { id: me } });
    expect(done.body.notes.map((n: any) => n.body)).toEqual(["Vic mistyped after a password change"]);
    const rule = (await h.call("GET", "/v1/alert-rules", { token })).body.data.find((r: any) => r.name === "Repeated failed sign-ins");
    expect(rule.quality).toMatchObject({ fired_30d: 1, open: 0, false_positive_rate: 1 });
    expect((await act(a.id, { action: "acknowledge" })).body.code).toBe("not_open");
  });

  it("lets read-only admins see alerts but not act on them", async () => {
    const email = uniqueEmail("ro");
    await h.call("POST", "/v1/users", { token, body: { email, given_name: "Ro", password: PASSWORD, roles: ["readonly"] } });
    const t = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    const list = await h.call("GET", "/v1/alerts?status=all", { token: t });
    expect(list.status).toBe(200);
    expect((await act(list.body.data[0].id, { action: "note", body: "hi" }, t)).status).toBe(403);
  });
});

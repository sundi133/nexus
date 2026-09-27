import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { audit } from "../src/audit/record.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** SaaS licenses: spend, seat holders, and which seats are used, from browsers and SSO sign-ins. */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let viewer = "";
let token = "";
const people: Record<string, { id: string; email: string }> = {};

const sync = (user: string, events: unknown[]) =>
  h.app.request("/v1/browser/extension/sync", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `NexusBrowser ${token}` },
    body: JSON.stringify({ user, extension_version: "0.2.0", policy_version: "", events }),
  });
const visit = (app: string) => ({ at: new Date().toISOString(), kind: "saas", action: "allowed", app, host: "", count: 1 });

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "License Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  for (const n of ["ana", "ben", "cat", "dan"]) {
    const email = uniqueEmail(n);
    people[n] = { email, id: (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: n, password: PASSWORD } })).body.id };
  }
  const v = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: v, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  viewer = (await h.call("POST", "/v1/auth/login", { body: { email: v, password: PASSWORD } })).body.token;
  token = (await h.call("POST", "/v1/browser/tokens", { token: admin, body: { name: "All" } })).body.token;
  const cur = (await h.call("GET", "/v1/browser/policy", { token: admin })).body;
  await h.call("PUT", "/v1/browser/policy", { token: admin, body: { apps: {}, dlp: { detectors: cur.dlp.detectors, custom: [] }, uploads: "allow", message: "", saas_discovery: true } });
});
afterAll(() => h.close());

describe("SaaS licenses", () => {
  let figma = "";
  let slack = "";

  it("tracks seats from a list: used, unused, and held by people who left", async () => {
    const r = await h.call("POST", "/v1/saas/licenses", { token: admin, body: { app_key: "figma", plan: "Professional", seats: 5, unit_cost: 15, billing: "monthly", seat_source: "list", renews_on: new Date(Date.now() + 20 * 86_400_000).toISOString().slice(0, 10) } });
    expect(r.status).toBe(201);
    figma = r.body.id;
    expect(r.body).toMatchObject({ app_name: "Figma", annual_cost: 900, renews_soon: true, holders: 0, unassigned: 5, reclaimable: 5, reclaimable_annual: 900 });

    const set = await h.call("PUT", `/v1/saas/licenses/${figma}/holders`, { token: admin, body: { emails: [people.ana!.email, people.ben!.email.toUpperCase(), people.cat!.email, "contractor@agency.example"] } });
    expect(set.body).toEqual({ holders: 4, added: 4, removed: 0 });
    await sync(people.ana!.email, [visit("figma")]);
    await h.call("POST", `/v1/users/${people.cat!.id}/offboard`, { token: admin, body: { reason: "Left" } });

    const one = (await h.call("GET", `/v1/saas/licenses/${figma}`, { token: viewer })).body;
    const status = Object.fromEntries(one.holders.map((x: any) => [x.email, x.status]));
    expect(status).toEqual({ [people.ana!.email]: "active", [people.ben!.email]: "inactive", [people.cat!.email]: "departed", "contractor@agency.example": "inactive" });
    expect(one.holders.find((x: any) => x.email === people.ana!.email)).toMatchObject({ via: "browser", last_used: expect.any(String) });
    // 1 unassigned + ben + cat + the contractor: 4 seats to reclaim, at $180 a year each.
    expect(one.license).toMatchObject({ holders: 4, active: 1, inactive: 2, departed: 1, unassigned: 1, reclaimable: 4, reclaimable_annual: 720, activity_from: ["browser"] });
  });

  it("takes seats from SSO assignments, and counts SSO sign-ins as use", async () => {
    const app = (await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "oidc", name: "Slack", redirect_uris: ["https://slack.example.com/cb"] } })).body.app;
    await h.call("POST", `/v1/apps/${app.id}/assignments`, { token: admin, body: { principals: [{ type: "user", id: people.ana!.id }, { type: "user", id: people.dan!.id }] } });
    const r = await h.call("POST", "/v1/saas/licenses", { token: admin, body: { app_key: "slack", seats: 2, unit_cost: 87.5, currency: "USD" } });
    slack = r.body.id;
    expect(r.body).toMatchObject({ sso_app: { name: "Slack" }, holders: 2, annual_cost: 175, activity_from: ["browser", "sso"] });
    // Dan signs in to Slack through Nexus (recorded the way the SSO endpoints record it); Ana doesn't use it.
    const orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
    await h.deps.db.tenant(orgId, (tx) =>
      audit(tx, orgId, { meta: { ip: "", userAgent: "", requestId: "" } }, { type: "sso.login", actor: { type: "user", id: people.dan!.id, display: people.dan!.email }, target: { type: "application", id: app.id, display: "Slack" }, details: { protocol: "oidc" } }),
    );
    const one = (await h.call("GET", `/v1/saas/licenses/${slack}`, { token: admin })).body;
    const status = Object.fromEntries(one.holders.map((x: any) => [x.email, [x.status, x.via]]));
    expect(status).toEqual({ [people.ana!.email]: ["inactive", null], [people.dan!.email]: ["active", "sso"] });
    expect(one.license).toMatchObject({ active: 1, inactive: 1, reclaimable: 1, reclaimable_annual: 87.5 });
    expect((await h.call("PUT", `/v1/saas/licenses/${slack}/holders`, { token: admin, body: { emails: [] } })).body.code).toBe("seats_from_sso");
  });

  it("totals spend and what could be reclaimed; checks input", async () => {
    const all = (await h.call("GET", "/v1/saas/licenses", { token: viewer })).body;
    expect(all.data).toHaveLength(2);
    expect(all.totals).toEqual([expect.objectContaining({ currency: "USD", annual_cost: 1075, seats: 7 })]);
    expect(all.renewing_soon).toBe(1);
    expect((await h.call("POST", "/v1/saas/licenses", { token: viewer, body: { app_key: "zoom", seats: 1 } })).status).toBe(403);
    expect((await h.call("POST", "/v1/saas/licenses", { token: admin, body: { app_key: "not-real", seats: 1 } })).body.code).toBe("unknown_app");
    const upd = await h.call("PUT", `/v1/saas/licenses/${figma}`, { token: admin, body: { app_key: "figma", seats: 3, unit_cost: 15, billing: "monthly", seat_source: "list" } });
    expect(upd.body).toMatchObject({ seats: 3, unassigned: 0, annual_cost: 540 });
    expect((await h.call("DELETE", `/v1/saas/licenses/${slack}`, { token: admin })).status).toBe(204);
    expect((await h.call("GET", "/v1/saas/licenses", { token: admin })).body.data).toHaveLength(1);
  });
});

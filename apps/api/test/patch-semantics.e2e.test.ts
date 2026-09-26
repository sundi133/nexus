import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/**
 * PATCH changes only what it names. (Zod 4's `.partial()` keeps defaults, which
 * once made a PATCH reset every field it didn't mention: see schemas.patchOf.)
 */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Patch Co", email: uniqueEmail("p"), password: PASSWORD, given_name: "P" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
});
afterAll(() => h.close());

describe("PATCH leaves other fields alone", () => {
  it("for people", async () => {
    const u = (await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("u"), given_name: "Ada", family_name: "Lovelace", title: "Engineer", department: "R&D" } })).body;
    const r = await h.call("PATCH", `/v1/users/${u.id}`, { token: admin, body: { given_name: "Augusta" } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((await h.call("GET", `/v1/users/${u.id}`, { token: admin })).body).toMatchObject({ given_name: "Augusta", family_name: "Lovelace", title: "Engineer", department: "R&D" });
  });

  it("for groups", async () => {
    const g = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "Eng", description: "Everyone who builds" } })).body;
    await h.call("PATCH", `/v1/groups/${g.id}`, { token: admin, body: { name: "Engineering" } });
    expect((await h.call("GET", `/v1/groups/${g.id}`, { token: admin })).body).toMatchObject({ name: "Engineering", description: "Everyone who builds" });
  });

  it("for directory connections", async () => {
    const c = (await h.call("POST", "/v1/directory/scim", { token: admin, body: { name: "Okta", deprovision: "none" } })).body.data[0];
    expect(c).toMatchObject({ enabled: true, deprovision: "none" });
    const r = await h.call("PATCH", `/v1/directory/connections/${c.id}`, { token: admin, body: { invite_new_users: false } });
    expect(r.body.data[0]).toMatchObject({ enabled: true, deprovision: "none", invite_new_users: false });
  });
});

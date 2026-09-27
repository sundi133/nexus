import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Every catalog template installs with valid input, and produces a usable SSO config. */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";

beforeAll(async () => {
  h = await bootApp();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Catalog Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
});
afterAll(() => h.close());

type Field = { key: string; placeholder: string; pattern: string };
const valueFor = (key: string, f: Field) => {
  if (new RegExp(f.pattern).test(f.placeholder) && !f.placeholder.includes("…")) return f.placeholder;
  if (f.pattern.startsWith("^https://")) return `https://sp.example.com/${key}/${f.key}`;
  throw new Error(`${key}.${f.key}: no valid sample value (placeholder "${f.placeholder}" doesn't match ${f.pattern})`);
};

describe("the app catalog", () => {
  it("refuses a URL that isn't one, instead of failing", async () => {
    const r = await h.call("POST", "/v1/app-catalog/aws-identity-center/install", { token: admin, body: { fields: { acs_url: "https://…", entity_id: "https://…" } } });
    expect(r.status).toBe(400);
  });

  it("has the common apps, each installable", async () => {
    const list = (await h.call("GET", "/v1/app-catalog", { token: admin })).body.data as { key: string; name: string; protocol: "saml" | "oidc"; fields: Field[] }[];
    expect(list.length).toBeGreaterThanOrEqual(40);
    expect(new Set(list.map((t) => t.key)).size).toBe(list.length);
    for (const t of list) {
      const fields = Object.fromEntries(t.fields.map((f) => [f.key, valueFor(t.key, f)]));
      if (t.key === "aws") fields.provider_name = "Nexus";
      const r = await h.call("POST", `/v1/app-catalog/${t.key}/install`, { token: admin, body: { fields } });
      expect(r.status, `${t.key}: ${JSON.stringify(r.body)}`).toBe(201);
      const setupText = JSON.stringify(r.body);
      expect(setupText, `${t.key} left a placeholder unfilled`).not.toMatch(/\{\{(?!idp_|issuer|client_)[a-z_]+\}\}/);
    }
  });

  it("lists a directory of apps: templates first-class, the rest set up as generic SAML/OIDC", async () => {
    const d = (await h.call("GET", "/v1/app-directory", { token: admin })).body.data as { key: string; name: string; protocols: string[]; template: string | null }[];
    expect(d.length).toBeGreaterThanOrEqual(250);
    expect(new Set(d.map((x) => x.key)).size).toBe(d.length);
    expect(d.find((x) => x.name === "Zendesk")).toMatchObject({ template: "zendesk" });
    expect(d.find((x) => x.name === "Rippling")).toMatchObject({ template: null, protocols: ["saml"] });
    expect(d.filter((x) => x.template).length).toBeGreaterThanOrEqual(40);
  });
});

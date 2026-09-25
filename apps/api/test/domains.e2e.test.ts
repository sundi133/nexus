import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { recheckDomain } from "../src/org/domains.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Verified domains (ORG-02): DNS proof, exclusivity across organizations, restriction, daily re-check. */

const dns = new Map<string, string[]>(); // name → TXT values
const resolveTxt = async (name: string) => {
  const v = dns.get(name);
  if (!v) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  return v.map((x) => [x]);
};
const DOMAIN = `acme-${randomUUID().slice(0, 8)}.test`;

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let a = ""; // org that owns the domain
let b = ""; // another org
let orgA = "";
let domainId = "";

const domains = async (token = a) => (await h.call("GET", "/v1/org/domains", { token })).body.data as Record<string, any>[];

beforeAll(async () => {
  h = await bootApp({}, { resolveTxt });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  a = (await h.call("POST", "/v1/signup", { body: { organization_name: "Acme", email: uniqueEmail("a"), password: PASSWORD, given_name: "A" } })).body.token;
  b = (await h.call("POST", "/v1/signup", { body: { organization_name: "Rival", email: uniqueEmail("b"), password: PASSWORD, given_name: "B" } })).body.token;
  for (const t of [a, b]) await h.call("PATCH", "/v1/org/settings", { token: t, body: { mfa_policy: "off" } });
  orgA = (await h.call("GET", "/v1/me", { token: a })).body.organization.id;
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("verifying a domain", () => {
  it("refuses public mail providers and malformed domains", async () => {
    expect((await h.call("POST", "/v1/org/domains", { token: a, body: { domain: "gmail.com" } })).body.code).toBe("public_domain");
    expect((await h.call("POST", "/v1/org/domains", { token: a, body: { domain: "not a domain" } })).body.code).toBe("invalid_domain");
  });

  it("gives a TXT record to publish, and checks for it", async () => {
    const r = await h.call("POST", "/v1/org/domains", { token: a, body: { domain: DOMAIN.toUpperCase() } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const d = r.body.data[0];
    domainId = d.id;
    expect(d).toMatchObject({ domain: DOMAIN, status: "pending", record: { type: "TXT", name: `_nexus-verification.${DOMAIN}` } });
    expect(d.record.value).toMatch(/^nexus-verification=[A-Za-z0-9_-]{24}$/);

    let v = await h.call("POST", `/v1/org/domains/${domainId}/verify`, { token: a, body: {} });
    expect(v.body.data[0]).toMatchObject({ status: "pending", last_error: expect.stringContaining("No TXT record") });
    dns.set(d.record.name, ["v=spf1 -all"]);
    v = await h.call("POST", `/v1/org/domains/${domainId}/verify`, { token: a, body: {} });
    expect(v.body.data[0].last_error).toContain("not the Nexus one");
    dns.set(d.record.name, ["v=spf1 -all", d.record.value]);
    v = await h.call("POST", `/v1/org/domains/${domainId}/verify`, { token: a, body: {} });
    expect(v.body.data[0]).toMatchObject({ status: "verified", last_error: "" });
    expect((await h.call("GET", "/v1/audit/events?type=org.domain_verified", { token: a })).body.data[0].target.display).toBe(DOMAIN);
  });

  it("makes the domain exclusive to the organization", async () => {
    // Another org can list it but not verify it, even with its own record published.
    const other = (await h.call("POST", "/v1/org/domains", { token: b, body: { domain: DOMAIN } })).body.data[0];
    dns.set(other.record.name, [...dns.get(other.record.name)!, other.record.value]);
    expect((await h.call("POST", `/v1/org/domains/${other.id}/verify`, { token: b, body: {} })).body.code).toBe("domain_claimed");

    // …and can't add people from it, by any route.
    expect((await h.call("POST", "/v1/users", { token: b, body: { email: `sam@${DOMAIN}`, given_name: "Sam" } })).body.code).toBe("domain_not_allowed");
    const imp = await h.call("POST", "/v1/users/import", { token: b, body: { csv: `email,given_name\nsam@${DOMAIN},Sam`, dry_run: true } });
    expect(imp.body.rows[0]).toMatchObject({ action: "error", message: `${DOMAIN} is managed by another Nexus organization` });
    const signup = await h.call("POST", "/v1/signup", { body: { organization_name: "Squatter", email: `ceo@${DOMAIN}`, password: PASSWORD, given_name: "C" } });
    expect(signup).toMatchObject({ status: 409, body: { code: "domain_claimed" } });

    // The owner can.
    expect((await h.call("POST", "/v1/users", { token: a, body: { email: `sam@${DOMAIN}`, given_name: "Sam" } })).status).toBe(201);
    expect((await domains())[0]!.people).toBe(1);
  });

  it("can restrict an organization to its own domains", async () => {
    await h.call("PATCH", "/v1/org/settings", { token: a, body: { restrict_to_verified_domains: true } });
    const out = await h.call("POST", "/v1/users", { token: a, body: { email: uniqueEmail("contractor"), given_name: "Con" } });
    expect(out.body).toMatchObject({ code: "domain_not_allowed" });
    expect(out.body.title).toContain("Only people from your verified domains");
    expect((await h.call("POST", "/v1/users", { token: a, body: { email: `pat@${DOMAIN}`, given_name: "Pat" } })).status).toBe(201);
    await h.call("PATCH", "/v1/org/settings", { token: a, body: { restrict_to_verified_domains: false } });
  });
});

describe("daily re-check", () => {
  it("warns when the record disappears, then releases the domain after 7 days", async () => {
    const name = `_nexus-verification.${DOMAIN}`;
    const saved = dns.get(name)!;
    dns.delete(name);
    await recheckDomain(h.deps, orgA, domainId);
    expect((await domains())[0]).toMatchObject({ status: "failing" });
    let inbox = (await h.call("GET", "/v1/me/notifications?limit=3&filter=all", { token: a })).body.data;
    expect(inbox[0]).toMatchObject({ title: `Can't find the verification record for ${DOMAIN}`, severity: "warning" });

    // Still exclusive while failing.
    expect((await h.call("POST", "/v1/users", { token: b, body: { email: `x@${DOMAIN}`, given_name: "X" } })).body.code).toBe("domain_not_allowed");

    await owner.query("UPDATE org_domains SET failing_since = now() - interval '8 days' WHERE id = $1", [domainId]);
    await recheckDomain(h.deps, orgA, domainId);
    expect((await domains())[0]).toMatchObject({ status: "pending" });
    inbox = (await h.call("GET", "/v1/me/notifications?limit=3&filter=all", { token: a })).body.data;
    expect(inbox[0]).toMatchObject({ title: `${DOMAIN} is no longer verified`, severity: "critical" });
    // Released: now the other org could prove it.
    dns.set(name, saved);
    const other = (await domains(b)).find((d) => d.domain === DOMAIN)!;
    expect((await h.call("POST", `/v1/org/domains/${other.id}/verify`, { token: b, body: {} })).body.data.find((d: { domain: string }) => d.domain === DOMAIN).status).toBe("verified");
  });
});

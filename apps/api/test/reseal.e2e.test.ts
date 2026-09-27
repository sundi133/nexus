import { randomBytes } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { reseal } from "../src/platform/reseal.js";
import { Sealer } from "../src/platform/seal.js";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";

/** Rotating the seal key (ADR-024): reseal everything, then the old key can go. */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let orgId = "";
let token = "";
let totp = "";
const newKey = randomBytes(32);

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("rot");
  token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Rotate", email, password: PASSWORD, given_name: "R" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token })).body.organization.id;
  const f = await h.call("POST", "/v1/me/factors/totp", { token, body: {} });
  totp = f.body.secret;
  await h.call("POST", `/v1/me/factors/${f.body.id}/verify`, { token, body: { code: totpCode(totp) } });
  const slug = (await h.call("GET", "/v1/me", { token })).body.organization.slug;
  await h.app.request(`/oidc/${slug}/jwks`); // creates the org's signing key
  await h.call("POST", "/v1/event-destinations", { token, body: { kind: "splunk_hec", name: "S", url: "https://splunk.example.com/services/collector/event", secret: "hec-token" } });
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("seal key rotation", () => {
  it("re-encrypts every secret of the organization with the new key", async () => {
    const rotated = new Sealer([{ id: 2, key: newKey }, ...h.deps.cfg.sealKeys]);
    const dry = await reseal(process.env.NEXUS_DATABASE_OWNER_URL!, rotated, { dryRun: true, orgId });
    const count = (t: string, r = dry) => r.find((x) => x.table === t)!;
    expect(count("auth_factors").resealed).toBe(1);
    expect(count("signing_keys").resealed).toBeGreaterThanOrEqual(1); // the org's OIDC key
    expect(count("event_destinations").resealed).toBe(1);

    const real = await reseal(process.env.NEXUS_DATABASE_OWNER_URL!, rotated, { orgId });
    expect(real.every((r) => r.failed.length === 0)).toBe(true);
    const again = await reseal(process.env.NEXUS_DATABASE_OWNER_URL!, rotated, { dryRun: true, orgId });
    expect(again.every((r) => r.resealed === 0)).toBe(true); // idempotent

    // Only the new key is needed now.
    const onlyNew = new Sealer([{ id: 2, key: newKey }]);
    const f = (await owner.query("SELECT id, secret_sealed FROM auth_factors WHERE org_id = $1", [orgId])).rows[0];
    expect(onlyNew.open(f.secret_sealed, f.id).toString()).toBe(totp);
    const d = (await owner.query("SELECT id, secret FROM event_destinations WHERE org_id = $1", [orgId])).rows[0];
    expect(onlyNew.open(d.secret, `event_destination:${d.id}`).toString()).toBe("hec-token");
  });

  it("reports secrets it can't open instead of corrupting them", async () => {
    const stranger = new Sealer([{ id: 3, key: randomBytes(32) }]);
    const r = await reseal(process.env.NEXUS_DATABASE_OWNER_URL!, stranger, { dryRun: true, orgId });
    expect(r.find((x) => x.table === "auth_factors")!.failed).toHaveLength(1);
  });
});

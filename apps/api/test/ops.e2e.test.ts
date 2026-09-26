import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig, validateProd } from "../src/config.js";
import { LATEST_MIGRATION, migrate } from "../src/platform/migrate.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Operability: health, readiness, metrics, security headers, production config checks, job retention. */

let h: Awaited<ReturnType<typeof bootApp>>;
let secured: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;

beforeAll(async () => {
  h = await bootApp();
  secured = await bootApp({ metricsToken: "metrics-token-0123456789abcdef" });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
});
afterAll(async () => {
  await owner.end();
  await h.close();
  await secured.close();
});

describe("health", () => {
  it("answers liveness and readiness (database reachable, schema current)", async () => {
    expect((await h.app.request("/healthz")).status).toBe(200);
    const r = await h.app.request("/readyz");
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ok: true, schema: LATEST_MIGRATION });
  });
});

describe("metrics", () => {
  it("exposes request, job and queue metrics in Prometheus format", async () => {
    await h.call("POST", "/v1/signup", { body: { organization_name: "Metrics", email: uniqueEmail("m"), password: PASSWORD, given_name: "M" } });
    const r = await h.app.request("/metrics");
    expect(r.headers.get("content-type")).toContain("text/plain");
    const text = await r.text();
    expect(text).toMatch(/nexus_http_requests_total\{method="POST",route="\/v1\/signup",status="2xx"\} \d+/);
    expect(text).toContain('nexus_http_request_duration_seconds_bucket{method="POST",route="/v1/signup",le="0.5"}');
    expect(text).toContain("# TYPE nexus_jobs gauge");
    expect(text).not.toMatch(/route="\/v1\/users\/[0-9a-f-]{36}"/); // templates, never raw IDs
  });

  it("requires the scrape token when one is configured", async () => {
    expect((await secured.app.request("/metrics")).status).toBe(401);
    expect((await secured.app.request("/metrics", { headers: { authorization: "Bearer wrong" } })).status).toBe(401);
    expect((await secured.app.request("/metrics", { headers: { authorization: "Bearer metrics-token-0123456789abcdef" } })).status).toBe(200);
  });
});

describe("security headers", () => {
  it("marks API responses as uncacheable, unsniffable and unframeable", async () => {
    const r = await h.app.request("/v1/users");
    expect(r.status).toBe(401);
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
    expect(r.headers.get("referrer-policy")).toBe("no-referrer");
    expect(r.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe("production configuration", () => {
  it("refuses development settings, listing every problem", () => {
    const problems = validateProd(loadConfig({ NEXUS_ENV: "prod", NEXUS_SEAL_KEY: Buffer.alloc(32).toString("base64") }), { NEXUS_ENV: "prod" });
    expect(problems).toEqual(
      expect.arrayContaining([
        "NEXUS_DATABASE_URL is required",
        "NEXUS_PUBLIC_URL must be https (got http://localhost:3100)",
        "Database URLs still use the development passwords",
        "NEXUS_METRICS_TOKEN is required",
      ]),
    );
  });

  it("accepts a proper production setup", () => {
    const env = {
      NEXUS_ENV: "prod",
      NEXUS_SEAL_KEY: Buffer.alloc(32, 7).toString("base64"),
      NEXUS_DATABASE_URL: "postgres://nexus_app:s3cret-app@db.internal:5432/nexus",
      NEXUS_DATABASE_OWNER_URL: "postgres://nexus_owner:s3cret-owner@db.internal:5432/nexus",
      NEXUS_PUBLIC_URL: "https://acme.nexus.votal.ai",
      NEXUS_API_PUBLIC_URL: "https://api.nexus.votal.ai",
      NEXUS_SMTP_URL: "smtps://user:pass@smtp.example.com:465",
      NEXUS_MAIL_FROM: "Votal Nexus <no-reply@nexus.votal.ai>",
      NEXUS_METRICS_TOKEN: "a-long-random-scrape-token-1234",
    };
    expect(validateProd(loadConfig(env), env)).toEqual([]);
  });
});

describe("migrations", () => {
  it("records a checksum per migration, and refuses to run when an applied one was edited", async () => {
    const ownerUrl = process.env.NEXUS_DATABASE_OWNER_URL!;
    const row = async () => (await owner.query("SELECT checksum FROM schema_migrations WHERE version = '0001_core.sql'")).rows[0].checksum as string;
    expect(await row()).toMatch(/^[0-9a-f]{64}$/);
    const real = await row();
    await owner.query("UPDATE schema_migrations SET checksum = $1 WHERE version = '0001_core.sql'", ["0".repeat(64)]);
    try {
      await expect(migrate(ownerUrl)).rejects.toThrow("migration 0001_core.sql was changed after it was applied");
    } finally {
      await owner.query("UPDATE schema_migrations SET checksum = $1 WHERE version = '0001_core.sql'", [real]);
    }
    await expect(migrate(ownerUrl)).resolves.toBeUndefined();
  });
});

describe("job retention", () => {
  it("prunes old finished jobs, keeping recent and dead ones longer", async () => {
    const org = (await owner.query("SELECT id FROM organizations LIMIT 1")).rows[0].id;
    const mk = async (status: string, age: string) => {
      const id = randomUUID();
      await owner.query(`INSERT INTO jobs (id, org_id, kind, status, finished_at) VALUES ($1, $2, 'test.old', $3, now() - $4::interval)`, [id, org, status, age]);
      return id;
    };
    const oldDone = await mk("done", "8 days");
    const newDone = await mk("done", "1 day");
    const oldDead = await mk("dead", "10 days");
    await owner.query("SELECT nexus_prune_jobs()");
    const left = (await owner.query("SELECT id FROM jobs WHERE id = ANY($1)", [[oldDone, newDone, oldDead]])).rows.map((r) => r.id);
    expect(left.sort()).toEqual([newDone, oldDead].sort());
  });
});

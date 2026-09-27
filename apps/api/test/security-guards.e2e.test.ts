import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isPublicRoute, PUBLIC_ROUTES } from "../src/auth/public-routes.js";
import { bootApp } from "./harness.js";

/**
 * Standing security guards: they fail the build if a new table skips tenant
 * isolation, a new privileged function is unsafe, or a new endpoint forgets
 * to require authentication. Evidence for security reviews, by construction.
 */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("tenant isolation in the database", () => {
  it("enforces row-level security on every table (except migration bookkeeping and rate-limit counters)", async () => {
    const tables = (
      await owner.query(`
        SELECT c.relname AS name, c.relrowsecurity AS rls,
               (SELECT count(*)::int FROM pg_policy p WHERE p.polrelid = c.oid) AS policies,
               EXISTS (SELECT 1 FROM information_schema.columns col WHERE col.table_schema = 'public' AND col.table_name = c.relname AND col.column_name = 'org_id') AS tenant
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r'`)
    ).rows as { name: string; rls: boolean; policies: number; tenant: boolean }[];
    // rate_limits holds no tenant data: namespaced counters (e.g. "login:<email>|<ip>") shared by replicas.
    const exempt = new Set(["schema_migrations", "rate_limits"]);
    expect(tables.find((t) => t.name === "rate_limits")?.tenant).toBe(false);
    const unprotected = tables.filter((t) => !exempt.has(t.name) && (!t.rls || t.policies === 0)).map((t) => t.name);
    expect(unprotected).toEqual([]);
    expect(tables.length).toBeGreaterThan(40);
  });

  it("scopes every tenant table's policy to the current organization", async () => {
    const bad = (
      await owner.query(`
        SELECT c.relname AS name, pg_get_expr(p.polqual, p.polrelid) AS using_expr, pg_get_expr(p.polwithcheck, p.polrelid) AS check_expr
        FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
        WHERE EXISTS (SELECT 1 FROM information_schema.columns col WHERE col.table_schema = 'public' AND col.table_name = c.relname AND col.column_name = 'org_id')`)
    ).rows.filter((r: { using_expr: string | null; check_expr: string | null }) => !String(r.using_expr).includes("nexus_current_org()") || !String(r.check_expr ?? r.using_expr).includes("nexus_current_org()"));
    expect(bad).toEqual([]);
  });

  it("runs the application as a role that can't bypass it", async () => {
    const r = (await owner.query("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'nexus_app'")).rows[0];
    expect(r).toEqual({ rolsuper: false, rolbypassrls: false });
    const grants = (await owner.query("SELECT privilege_type FROM information_schema.role_table_grants WHERE grantee = 'nexus_app' AND table_name = 'schema_migrations'")).rows;
    expect(grants).toEqual([]);
  });

  it("keeps privileged functions narrow: fixed search_path, not callable by PUBLIC", async () => {
    const fns = (
      await owner.query(`
        SELECT p.proname AS name, p.proconfig AS config, has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.prosecdef`)
    ).rows as { name: string; config: string[] | null; public_exec: boolean }[];
    expect(fns.length).toBeGreaterThan(10);
    const unsafe = fns.filter((f) => !f.config?.some((c) => c.startsWith("search_path=")) || f.public_exec).map((f) => f.name);
    expect(unsafe).toEqual([]);
  });
});

describe("authentication on every endpoint", () => {
  const fill = (path: string) => path.replace(/\{[^}]+\}/g, "01a0d5f0-f8c9-70a7-8e5d-cf7f43c7df6b");

  it("requires credentials unless the endpoint is on the public list", async () => {
    const doc = (await (await h.app.request("/v1/openapi.json")).json()) as { paths: Record<string, Record<string, unknown>> };
    const results: string[] = [];
    let checked = 0;
    for (const [path, ops] of Object.entries(doc.paths)) {
      for (const method of Object.keys(ops).filter((m) => ["get", "post", "put", "patch", "delete"].includes(m))) {
        const key = `${method.toUpperCase()} ${path}`;
        const res = await h.app.request(fill(path), {
          method: method.toUpperCase(),
          headers: { "content-type": "application/json" },
          body: method === "get" || method === "delete" ? undefined : "{}",
        });
        checked++;
        if (res.status >= 500) results.push(`${key} → ${res.status}`);
        else if (!isPublicRoute(method.toUpperCase(), fill(path)) && res.status !== 401 && res.status !== 403) results.push(`${key} → ${res.status} without credentials`);
      }
    }
    expect(results).toEqual([]);
    expect(checked).toBeGreaterThan(140); // the sweep really covered the API
  });

  it("keeps the public list and the API description in step", async () => {
    const doc = (await (await h.app.request("/v1/openapi.json")).json()) as { paths: Record<string, Record<string, { security?: unknown[] }>> };
    const documentedPublic = Object.entries(doc.paths).flatMap(([path, ops]) =>
      Object.entries(ops).filter(([m, o]) => ["get", "post", "put", "patch", "delete"].includes(m) && !o.security?.length).map(([m]) => `${m.toUpperCase()} ${path}`),
    );
    const notAllowed = documentedPublic.filter((k) => {
      const [m, p] = k.split(" ") as [string, string];
      return !isPublicRoute(m, fill(p));
    });
    expect(notAllowed).toEqual([]); // documented as public but refused
    expect(PUBLIC_ROUTES.length).toBeLessThan(15); // the public surface stays small and deliberate
  });

  it("rejects forged and revoked credentials the same way", async () => {
    for (const token of ["nxs_forged", "nxk_forged", "Bearer", "not-a-token"]) {
      expect((await h.call("GET", "/v1/users", { token })).status).toBe(401);
    }
  });
});

describe("request size", () => {
  it("refuses bodies over 1 MB before reading them, except where more is needed", async () => {
    const h = await bootApp();
    const big = JSON.stringify({ email: `${"a".repeat(2 * 1024 * 1024)}@example.test`, password: "x" });
    const r = await h.app.request("/v1/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": String(big.length) }, body: big });
    expect(r.status).toBe(413);
    expect(((await r.json()) as { code: string }).code).toBe("too_large");
    // A 2 MB CSV import is fine (it's then checked for authentication like anything else).
    const csv = JSON.stringify({ csv: "a".repeat(2 * 1024 * 1024) });
    const i = await h.app.request("/v1/users/import", { method: "POST", headers: { "content-type": "application/json", "content-length": String(csv.length) }, body: csv });
    expect(i.status).toBe(401);
    await h.close();
  });
});

describe("who can create an organization", () => {
  it("is closed when configured, and 'first' allows none once one exists", async () => {
    const closed = await bootApp({ signup: "closed" });
    const r = await closed.call("POST", "/v1/signup", { body: { organization_name: "Nope", email: "nope@example.test", password: "correct-horse-battery-staple", given_name: "N" } });
    expect(r.body.code).toBe("signup_closed");
    await closed.close();
    const first = await bootApp({ signup: "first" }); // the test database already has organizations
    expect((await first.call("POST", "/v1/signup", { body: { organization_name: "Late", email: "late@example.test", password: "correct-horse-battery-staple", given_name: "L" } })).status).toBe(403);
    await first.close();
  });
});

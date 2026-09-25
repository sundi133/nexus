import type { JobRunner } from "./platform/jobs.js";
import { OpenAPIHono } from "@hono/zod-openapi";
import { getConnInfo } from "@hono/node-server/conninfo";
import { cors } from "hono/cors";
import { randomUUID } from "node:crypto";
import type { Deps, Env } from "./context.js";
import { registerAuditRoutes } from "./audit/routes.js";
import { sql } from "kysely";
import { loadPrincipal } from "./auth/guard.js";
import { metrics, renderMetrics } from "./platform/metrics.js";
import { LATEST_MIGRATION } from "./platform/migrate.js";
import { unauthorized } from "./platform/errors.js";
import { isPublicRoute } from "./auth/public-routes.js";
import { registerAuthRoutes } from "./auth/routes.js";
import { registerFederationRoutes } from "./federation/routes.js";
import { registerScimServer } from "./directory/scim/server.js";
import { scheduleGraceChecks } from "./devices/service.js";
import { registerMdmRoutes, scheduleMdmSyncs } from "./devices/mdm.js";
import { registerCommandRoutes } from "./devices/commands.js";
import { registerAccessRequestRoutes } from "./governance/routes.js";
import { scheduleAccessExpiry } from "./governance/requests.js";
import { registerAccessReviewRoutes, scheduleAccessReviews } from "./governance/reviews.js";
import { registerAiAgentRoutes } from "./ai-agents/routes.js";
import { registerMcpGateway } from "./mcp/gateway.js";
import { registerMcpRoutes } from "./mcp/routes.js";
import { scheduleMcpSyncs } from "./mcp/service.js";
import { registerPasskeyRoutes } from "./auth/passkeys.js";
import { registerPushRoutes } from "./auth/push.js";
import { registerGroupRoutes } from "./directory/groups.js";
import { scheduleDynamicGroups } from "./directory/dynamic-groups.js";
import { registerUserRoutes } from "./directory/users.js";
import { registerInvitationRoutes } from "./directory/invitations.js";
import { registerImportRoutes } from "./directory/import.js";
import { registerNotificationRoutes } from "./notify/routes.js";
import { registerOverviewRoutes } from "./overview/routes.js";
import { registerOrgRoutes } from "./org/routes.js";
import { registerAppRoutes } from "./sso/apps.js";
import { registerOidcRoutes } from "./sso/oidc.js";
import { registerSamlRoutes } from "./sso/saml.js";
import { registerCatalogRoutes } from "./sso/catalog.js";
import { registerKeyRoutes } from "./sso/key-routes.js";
import { registerAgentRoutes, registerReleaseDownloads } from "./devices/agent-api.js";
import { registerAgentUpdateRoutes } from "./devices/update-routes.js";
import { registerDirectorySyncRoutes } from "./directory/sync/routes.js";
import { registerProvisioningRoutes } from "./provisioning/routes.js";
import { registerOffboardingRoutes } from "./directory/offboarding.js";
import { registerApiKeyRoutes } from "./auth/api-keys.js";
import { registerRecoveryRoutes } from "./auth/recovery.js";
import { registerChannelRoutes } from "./notify/channels.js";
import { registerDomainRoutes, scheduleDomainRechecks } from "./org/domains.js";
import { registerBreakGlassRoutes } from "./directory/break-glass.js";
import { registerEventDestinationRoutes } from "./integrations/routes.js";
import { scheduleEventDelivery } from "./integrations/stream.js";
import { scheduleProvisioningReconcile } from "./provisioning/service.js";
import { scheduleDirectorySyncs } from "./directory/sync/service.js";
import { registerDeviceRoutes } from "./devices/routes.js";
import { registerDeviceTrustRoutes } from "./access/device-trust.js";
import { registerAccessPolicyRoutes } from "./access/routes.js";
import { ApiError, problem } from "./platform/errors.js";

export const API_INFO = {
  title: "Votal Nexus API",
  version: "0.1.0",
  description:
    "One API for the web console, Nexus Mobile, the CLI and your own integrations. Authenticate with `Authorization: Bearer <token>`. Errors use RFC 9457 `application/problem+json` with a stable `code`.",
};

export function createApp(deps: Deps) {
  const app = new OpenAPIHono<Env>({
    defaultHook: (result, c) => {
      if (!result.success) {
        return problem(
          c,
          new ApiError(400, "invalid_request", "Some fields are invalid", {
            errors: result.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
          }),
        );
      }
    },
  });

  app.use("*", async (c, next) => {
    const fwd = deps.cfg.trustProxy ? c.req.header("x-forwarded-for")?.split(",")[0]?.trim() : undefined;
    let ip = fwd ?? "";
    if (!ip) {
      try {
        ip = getConnInfo(c).remote.address ?? "";
      } catch {
        ip = "";
      }
    }
    const requestId = c.req.header("x-request-id") ?? randomUUID();
    c.set("deps", deps);
    c.set("meta", { ip, userAgent: c.req.header("user-agent") ?? "", requestId });
    c.header("X-Request-Id", requestId);
    // Security headers: the API only serves JSON (and a few protocol responses) to other code.
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
    c.header("X-Frame-Options", "DENY");
    if (deps.cfg.env === "prod") c.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    const started = performance.now();
    await next();
    if (c.req.path.startsWith("/v1/") && !c.res.headers.has("cache-control")) c.header("Cache-Control", "no-store");
    // Metrics and a log line per request, by route template (never raw IDs).
    const route = c.req.routePath && c.req.routePath !== "*" && c.req.routePath !== "/v1/*" ? c.req.routePath : "unmatched";
    const seconds = (performance.now() - started) / 1000;
    const status = c.res.status;
    metrics.httpRequests.inc({ method: c.req.method, route, status: `${Math.floor(status / 100)}xx` });
    metrics.httpDuration.observe({ method: c.req.method, route }, seconds);
    if (deps.cfg.env !== "test" && route !== "/healthz" && route !== "/metrics") {
      const p = c.get("principal");
      const line = { ts: new Date().toISOString(), level: status >= 500 ? "error" : "info", msg: "request", method: c.req.method, route, status, ms: Math.round(seconds * 1000), request_id: requestId, org_id: p?.orgId, actor: p ? (p.apiKey ? `key:${p.apiKey.id}` : `user:${p.userId}`) : undefined, ip };
      console.log(deps.cfg.logFormat === "json" ? JSON.stringify(line) : `${line.method} ${route} ${status} ${line.ms}ms`);
    }
  });

  app.use("/v1/*", cors({ origin: deps.cfg.publicUrl, credentials: false, maxAge: 600 }));
  app.use("/v1/*", loadPrincipal);
  // Deny by default, before any request validation runs.
  app.use("/v1/*", async (c, next) => {
    if (!c.get("principal") && !isPublicRoute(c.req.method, c.req.path)) throw unauthorized();
    await next();
  });

  app.onError((err, c) => {
    if (err instanceof ApiError) return problem(c, err);
    console.error(`[${c.get("meta")?.requestId}]`, err);
    return problem(c, new ApiError(500, "internal", "Something went wrong on our side"));
  });
  app.notFound((c) => problem(c, new ApiError(404, "not_found", "No such endpoint")));

  // Liveness: the process answers. Readiness: it can reach the database and the schema is current.
  app.get("/healthz", (c) => c.json({ ok: true }));
  app.get("/readyz", async (c) => {
    try {
      const v = await deps.db.unscoped(async (tx) => (await sql<{ v: string | null }>`SELECT nexus_schema_version() AS v`.execute(tx)).rows[0]!.v);
      const want = LATEST_MIGRATION;
      if (want && v !== want) return c.json({ ok: false, reason: `schema at ${v}, code expects ${want}` }, 503);
      return c.json({ ok: true, schema: v }, 200);
    } catch (err) {
      return c.json({ ok: false, reason: `database unavailable: ${(err as Error).message}` }, 503);
    }
  });
  // Prometheus scrape endpoint. Needs NEXUS_METRICS_TOKEN (always, in production).
  app.get("/metrics", async (c) => {
    const token = deps.cfg.metricsToken;
    if ((token || deps.cfg.env === "prod") && c.req.header("authorization") !== `Bearer ${token}`) return c.text("unauthorized", 401);
    const queue = await deps.db
      .unscoped(async (tx) => (await sql<{ status: string; kind: string; n: number }>`SELECT * FROM nexus_job_queue_stats()`.execute(tx)).rows)
      .catch(() => []);
    return c.text(
      renderMetrics([{ name: "nexus_jobs", help: "Background jobs by status and kind", values: queue.map((q) => [{ status: q.status, kind: q.kind }, q.n] as [Record<string, string>, number]) }]),
      200,
      { "content-type": "text/plain; version=0.0.4" },
    );
  });

  registerAuthRoutes(app);
  registerFederationRoutes(app);
  registerScimServer(app);
  registerMdmRoutes(app);
  registerCommandRoutes(app);
  registerAccessRequestRoutes(app);
  registerAccessReviewRoutes(app);
  registerAiAgentRoutes(app);
  registerMcpRoutes(app);
  registerMcpGateway(app);
  registerPasskeyRoutes(app);
  registerPushRoutes(app);
  registerImportRoutes(app);
  registerUserRoutes(app);
  registerInvitationRoutes(app);
  registerGroupRoutes(app);
  registerAuditRoutes(app);
  registerNotificationRoutes(app);
  registerOverviewRoutes(app);
  registerOrgRoutes(app);
  registerAppRoutes(app);
  registerOidcRoutes(app);
  registerSamlRoutes(app);
  registerCatalogRoutes(app);
  registerKeyRoutes(app);
  registerAgentRoutes(app);
  registerReleaseDownloads(app);
  registerAgentUpdateRoutes(app);
  registerDirectorySyncRoutes(app);
  registerProvisioningRoutes(app);
  registerOffboardingRoutes(app);
  registerApiKeyRoutes(app);
  registerRecoveryRoutes(app);
  registerChannelRoutes(app);
  registerDomainRoutes(app);
  registerBreakGlassRoutes(app);
  registerEventDestinationRoutes(app);
  registerDeviceRoutes(app);
  registerDeviceTrustRoutes(app);
  registerAccessPolicyRoutes(app);

  app.openAPIRegistry.registerComponent("securitySchemes", "bearer", {
    type: "http",
    scheme: "bearer",
    description: "Session token (`nxs_…`) from /v1/auth/login or /v1/signup",
  });
  app.doc31("/v1/openapi.json", { openapi: "3.1.0", info: API_INFO, servers: [{ url: "/" }] });

  return app;
}

/** Periodic work run by the job loop (not by HTTP requests). Features add theirs here. */
export function registerSchedules(jobs: JobRunner, deps: Deps) {
  scheduleDirectorySyncs(jobs, deps);
  scheduleProvisioningReconcile(jobs, deps);
  scheduleEventDelivery(jobs, deps);
  scheduleDomainRechecks(jobs, deps);
  scheduleGraceChecks(jobs, deps);
  scheduleMdmSyncs(jobs, deps);
  scheduleAccessExpiry(jobs, deps);
  scheduleAccessReviews(jobs, deps);
  scheduleDynamicGroups(jobs, deps);
  scheduleMcpSyncs(jobs, deps);
}

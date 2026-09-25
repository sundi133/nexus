import type { JobRunner } from "./platform/jobs.js";
import { OpenAPIHono } from "@hono/zod-openapi";
import { getConnInfo } from "@hono/node-server/conninfo";
import { cors } from "hono/cors";
import { randomUUID } from "node:crypto";
import type { Deps, Env } from "./context.js";
import { registerAuditRoutes } from "./audit/routes.js";
import { loadPrincipal } from "./auth/guard.js";
import { unauthorized } from "./platform/errors.js";
import { isPublicRoute } from "./auth/public-routes.js";
import { registerAuthRoutes } from "./auth/routes.js";
import { registerPasskeyRoutes } from "./auth/passkeys.js";
import { registerPushRoutes } from "./auth/push.js";
import { registerGroupRoutes } from "./directory/groups.js";
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
    await next();
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

  app.get("/healthz", (c) => c.json({ ok: true }));

  registerAuthRoutes(app);
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
}

import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa, requireSession } from "../auth/guard.js";
import { ApiError, badRequest, notFound } from "../platform/errors.js";
import { assertSafeUrl, UnsafeUrlError } from "../platform/outbound.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { postToSlack, slackAad } from "./deliver.js";

const Level = z.enum(["all", "important", "critical"]).openapi({ description: "all | important (warnings and critical) | critical only" });
const Prefs = z.object({ email: Level, push: Level }).openapi("NotificationPreferences");
const Channels = z.object({ slack_configured: z.boolean(), slack_min_severity: z.enum(["info", "warning", "critical"]) }).openapi("AlertChannels");
const Delivery = z.object({ channel: z.enum(["push", "email", "slack"]), status: z.enum(["sent", "failed", "skipped"]), detail: z.string(), at: z.string() }).openapi("NotificationDelivery");

export function registerChannelRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/me/notification-preferences", tags: ["Notifications"], summary: "Which notifications reach your phone and email", security: bearer, responses: { 200: json(Prefs), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const r = await c.get("deps").db.tenant(p.orgId, (tx) => tx.selectFrom("notification_preferences").select(["email", "push"]).where("user_id", "=", p.userId).executeTakeFirst());
      return c.json({ email: r?.email ?? "important", push: r?.push ?? "important" }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/me/notification-preferences",
      tags: ["Notifications"],
      summary: "Choose which notifications reach your phone and email",
      description: "Critical security notifications always reach both.",
      security: bearer,
      request: body(Prefs),
      responses: { 200: json(Prefs), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const input = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx
          .insertInto("notification_preferences")
          .values({ user_id: p.userId, org_id: p.orgId, ...input })
          .onConflict((oc) => oc.column("user_id").doUpdateSet({ ...input, updated_at: new Date() }))
          .execute(),
      );
      return c.json(input, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/notifications/{id}/deliveries",
      tags: ["Notifications"],
      summary: "Where a notification was delivered",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ data: z.array(Delivery) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const n = await tx.selectFrom("notifications").select("id").where("id", "=", id).where("recipient_user_id", "=", p.userId).executeTakeFirst();
        if (!n) throw notFound("Notification");
        return tx.selectFrom("notification_deliveries").select(["channel", "status", "detail", "at"]).where("notification_id", "=", id).orderBy("at").execute();
      });
      return c.json({ data: rows.map((r) => ({ ...r, at: iso(r.at) })) }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/org/alert-channels", tags: ["Notifications"], summary: "Where org-wide alerts go besides admins' inboxes", security: bearer, responses: { 200: json(Channels), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const r = await c.get("deps").db.tenant(p.orgId, (tx) => tx.selectFrom("org_alert_channels").selectAll().executeTakeFirst());
      return c.json({ slack_configured: !!r?.slack_webhook, slack_min_severity: r?.slack_min_severity ?? "warning" }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/org/alert-channels",
      tags: ["Notifications"],
      summary: "Send org-wide alerts to a Slack channel (requires recent MFA)",
      description: "`slack_webhook_url`: a Slack incoming-webhook URL; null removes it; omit to keep the current one.",
      security: bearer,
      request: body(z.object({ slack_webhook_url: z.string().max(500).nullable().optional(), slack_min_severity: z.enum(["info", "warning", "critical"]) })),
      responses: { 200: json(Channels), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      if (input.slack_webhook_url) {
        try {
          await assertSafeUrl(input.slack_webhook_url, { allowPrivate: deps.cfg.allowPrivateOutbound });
        } catch (err) {
          if (err instanceof UnsafeUrlError) throw badRequest("unsafe_url", err.message);
          throw err;
        }
      }
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const webhook = input.slack_webhook_url === undefined ? undefined : input.slack_webhook_url === null ? null : deps.sealer.seal(Buffer.from(input.slack_webhook_url), slackAad(p.orgId));
        await tx
          .insertInto("org_alert_channels")
          .values({ org_id: p.orgId, slack_webhook: webhook ?? null, slack_min_severity: input.slack_min_severity })
          .onConflict((oc) => oc.column("org_id").doUpdateSet({ ...(webhook !== undefined ? { slack_webhook: webhook } : {}), slack_min_severity: input.slack_min_severity, updated_at: new Date() }))
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "org.alert_channels_changed",
          target: { type: "organization", id: p.orgId },
          details: { slack: input.slack_webhook_url === undefined ? "unchanged" : input.slack_webhook_url ? "set" : "removed", slack_min_severity: input.slack_min_severity },
        });
        const r = await tx.selectFrom("org_alert_channels").selectAll().executeTakeFirstOrThrow();
        return { slack_configured: !!r.slack_webhook, slack_min_severity: r.slack_min_severity };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/org/alert-channels/test", tags: ["Notifications"], summary: "Send a test alert to Slack", security: bearer, responses: { 204: { description: "Delivered" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const r = await deps.db.tenant(p.orgId, (tx) => tx.selectFrom("org_alert_channels").selectAll().executeTakeFirst());
      if (!r?.slack_webhook) throw notFound("Slack channel");
      try {
        await postToSlack(deps.sealer.open(r.slack_webhook, slackAad(p.orgId)).toString(), { title: "Test alert from Votal Nexus", body: `Sent by ${p.email}. Security alerts will appear here.`, severity: "info", link: "/", category: "test" }, deps.cfg.publicUrl);
      } catch (err) {
        throw new ApiError(422, "slack_unreachable", (err as Error).message);
      }
      return c.body(null, 204);
    },
  );
}

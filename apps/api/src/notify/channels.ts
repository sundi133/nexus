import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa, requireSession } from "../auth/guard.js";
import { ApiError, badRequest, notFound } from "../platform/errors.js";
import { assertSafeUrl, UnsafeUrlError } from "../platform/outbound.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { sql } from "kysely";
import { loadPrefs, postToSlack, slackAad } from "./deliver.js";
import { isTimeZone } from "./schedule.js";

const Level = z.enum(["all", "important", "critical"]).openapi({ description: "all | important (warnings and critical) | critical only" });
const Time = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, "A time like 22:00");
const Prefs = z
  .object({
    email: Level,
    push: Level,
    timezone: z.string().max(64).refine(isTimeZone, "An IANA time zone like Europe/Berlin").openapi({ description: "Used for quiet hours and the digest" }),
    quiet_hours: z.object({ enabled: z.boolean(), start: Time, end: Time }).openapi({ description: "Hold non-critical push and email during these hours; a summary follows when they end" }),
    digest: z.object({ enabled: z.boolean(), time: Time }).openapi({ description: "Send non-critical email as one daily digest at this time" }),
  })
  .openapi("NotificationPreferences");
type PrefsT = z.infer<typeof Prefs>;
const toApi = (r: Awaited<ReturnType<typeof loadPrefs>>): PrefsT => ({
  email: r.email,
  push: r.push,
  timezone: r.timezone,
  quiet_hours: { enabled: r.quiet_enabled, start: r.quiet_start, end: r.quiet_end },
  digest: { enabled: r.digest_enabled, time: r.digest_time },
});
const Channels = z.object({ slack_configured: z.boolean(), slack_min_severity: z.enum(["info", "warning", "critical"]) }).openapi("AlertChannels");
const Delivery = z.object({ channel: z.enum(["push", "email", "slack"]), status: z.enum(["sent", "failed", "skipped", "held"]), detail: z.string(), at: z.string() }).openapi("NotificationDelivery");

export function registerChannelRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/me/notification-preferences", tags: ["Notifications"], summary: "Which notifications reach your phone and email", security: bearer, responses: { 200: json(Prefs), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      return c.json(toApi(await c.get("deps").db.tenant(p.orgId, (tx) => loadPrefs(tx, p.userId))), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/me/notification-preferences",
      tags: ["Notifications"],
      summary: "Choose which notifications reach your phone and email, and when",
      description: "Critical security notifications always reach both, right away. Omitted fields keep their current values.",
      security: bearer,
      request: body(Prefs.partial()),
      responses: { 200: json(Prefs), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const cur = toApi(await loadPrefs(tx, p.userId));
        const next = { ...cur, ...input };
        const row = {
          email: next.email,
          push: next.push,
          timezone: next.timezone,
          quiet_enabled: next.quiet_hours.enabled,
          quiet_start: next.quiet_hours.start,
          quiet_end: next.quiet_hours.end,
          digest_enabled: next.digest.enabled,
          digest_time: next.digest.time,
        };
        await tx
          .insertInto("notification_preferences")
          .values({ user_id: p.userId, org_id: p.orgId, ...row })
          .onConflict((oc) => oc.column("user_id").doUpdateSet({ ...row, updated_at: new Date() }))
          .execute();
        // Anything already held is re-timed under the new settings (the summary re-checks and waits if it should).
        await sql`UPDATE jobs SET run_at = now() WHERE kind = 'notify.summary' AND status = 'queued' AND dedupe_key LIKE ${`notify.summary:${p.userId}:%`}`.execute(tx);
        return next;
      });
      return c.json(out, 200);
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

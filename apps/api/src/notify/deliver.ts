import type { Deps } from "../context.js";
import { layout } from "../platform/mailer.js";
import { newId } from "../platform/ids.js";
import { enqueue, registerJobHandler } from "../platform/jobs.js";
import { assertSafeUrl, networkError } from "../platform/outbound.js";
import type { Tx } from "../platform/db.js";
import { hhmm, inWindow, nextLocalTime } from "./schedule.js";

/**
 * Delivers inbox notifications to the recipient's phone and email (NTF-04/06/07)
 * and org-wide alerts to Slack, logging every attempt (NTF-11). Push payloads
 * stay content-free: a generic title and an ID the app resolves over the API.
 * Critical notifications always go out, whatever the preferences. Others can
 * wait for the end of quiet hours or for the daily email digest, and then go
 * out as one summary per channel.
 */

export const SEVERITY = { info: 0, warning: 1, critical: 2 } as const;
const LEVEL = { all: 0, important: 1, critical: 2 } as const;
export type Severity = keyof typeof SEVERITY;
export type Level = keyof typeof LEVEL;

export const slackAad = (orgId: string) => `org_alert_channels:${orgId}`;

async function record(tx: Tx, orgId: string, notificationId: string | null, channel: "push" | "email" | "slack", status: "sent" | "failed" | "skipped" | "held", detail: string) {
  await tx.insertInto("notification_deliveries").values({ id: newId(), org_id: orgId, notification_id: notificationId, channel, status, detail }).execute();
}

export const wants = (level: Level, severity: Severity) => severity === "critical" || SEVERITY[severity] >= LEVEL[level];

export type Prefs = {
  email: Level;
  push: Level;
  timezone: string;
  quiet_enabled: boolean;
  quiet_start: string;
  quiet_end: string;
  digest_enabled: boolean;
  digest_time: string;
};
export const DEFAULT_PREFS: Prefs = { email: "important", push: "important", timezone: "UTC", quiet_enabled: false, quiet_start: "22:00", quiet_end: "07:00", digest_enabled: false, digest_time: "08:00" };

export async function loadPrefs(tx: Tx, userId: string): Promise<Prefs> {
  const r = await tx
    .selectFrom("notification_preferences")
    .select(["email", "push", "timezone", "quiet_enabled", "quiet_start", "quiet_end", "digest_enabled", "digest_time"])
    .where("user_id", "=", userId)
    .executeTakeFirst();
  return r ? (r as Prefs) : { ...DEFAULT_PREFS };
}

/** Whether a (non-critical) notification on this channel should wait, and until when. */
export function holdUntil(prefs: Prefs, channel: "push" | "email", now = new Date()): { until: Date; reason: string } | null {
  if (channel === "email" && prefs.digest_enabled) return { until: nextLocalTime(now, prefs.digest_time, prefs.timezone), reason: `In the daily digest at ${prefs.digest_time}` };
  if (prefs.quiet_enabled && inWindow(now, prefs.quiet_start, prefs.quiet_end, prefs.timezone)) {
    return { until: nextLocalTime(now, prefs.quiet_end, prefs.timezone), reason: `Quiet hours until ${prefs.quiet_end}` };
  }
  return null;
}

/**
 * When the summary of what's held should go out: the first digest time after
 * the oldest held notification, or the end of quiet hours if they're on now.
 */
export function summaryDue(prefs: Prefs, channel: "push" | "email", heldSince: Date, now = new Date()): Date {
  if (channel === "email" && prefs.digest_enabled) return nextLocalTime(new Date(heldSince.getTime() - 60_000), prefs.digest_time, prefs.timezone);
  if (prefs.quiet_enabled && inWindow(now, prefs.quiet_start, prefs.quiet_end, prefs.timezone)) return nextLocalTime(now, prefs.quiet_end, prefs.timezone);
  return now;
}

export const summaryKey = (userId: string, channel: "push" | "email") => `notify.summary:${userId}:${channel}`;

async function hold(tx: Tx, orgId: string, userId: string, notificationId: string, channel: "push" | "email", h: { until: Date; reason: string }) {
  await record(tx, orgId, notificationId, channel, "held", h.reason);
  // One summary per user and channel: later notifications join the one already scheduled.
  await enqueue(tx, orgId, "notify.summary", { user_id: userId, channel }, { runAt: h.until, dedupeKey: summaryKey(userId, channel), maxAttempts: 4 });
}

export async function deliverNotification(deps: Deps, orgId: string, notificationId: string) {
  const ctx = await deps.db.tenant(orgId, async (tx) => {
    const n = await tx.selectFrom("notifications").selectAll().where("id", "=", notificationId).executeTakeFirst();
    if (!n) return null;
    const user = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", n.recipient_user_id).executeTakeFirst();
    const prefs = await loadPrefs(tx, n.recipient_user_id);
    const regs = await tx.selectFrom("push_registrations").select(["id", "platform", "token"]).where("user_id", "=", n.recipient_user_id).execute();
    const done = new Set((await tx.selectFrom("notification_deliveries").select("channel").where("notification_id", "=", notificationId).where("status", "in", ["sent", "skipped", "held"]).execute()).map((d) => d.channel));
    return { n, user, prefs, regs, done };
  });
  if (!ctx?.user || (ctx.user.status !== "active" && ctx.user.status !== "staged")) return;
  const { n, user, prefs, regs, done } = ctx;
  const severity = n.severity as Severity;
  const now = new Date();
  const held = (channel: "push" | "email") => (severity === "critical" ? null : holdUntil(prefs, channel, now));

  // Push: content-free.
  if (!done.has("push")) {
    if (!wants(prefs.push, severity)) {
      await deps.db.tenant(orgId, (tx) => record(tx, orgId, n.id, "push", "skipped", `Below their push setting (${prefs.push})`));
    } else if (!regs.length) {
      await deps.db.tenant(orgId, (tx) => record(tx, orgId, n.id, "push", "skipped", "No phone paired"));
    } else if (held("push")) {
      await deps.db.tenant(orgId, (tx) => hold(tx, orgId, n.recipient_user_id, n.id, "push", held("push")!));
    } else {
      const title = severity === "critical" ? "Security alert" : severity === "warning" ? "Needs your attention" : "New notification";
      const results = await Promise.all(regs.map(async (r) => ({ r, res: await deps.push.send({ platform: r.platform, token: r.token }, { title, category: n.category, id: n.id, priority: severity === "critical" ? "high" : "normal" }) })));
      const ok = results.filter((x) => x.res.ok).length;
      const dead = results.filter((x) => x.res.invalidToken).map((x) => x.r.id);
      await deps.db.tenant(orgId, async (tx) => {
        if (dead.length) await tx.deleteFrom("push_registrations").where("id", "in", dead).execute(); // uninstalled apps
        await record(tx, orgId, n.id, "push", ok ? "sent" : "failed", `${ok} of ${regs.length} phone${regs.length === 1 ? "" : "s"}${dead.length ? `; removed ${dead.length} expired` : ""}`);
      });
    }
  }

  // Email.
  if (!done.has("email")) {
    if (!wants(prefs.email, severity)) {
      await deps.db.tenant(orgId, (tx) => record(tx, orgId, n.id, "email", "skipped", `Below their email setting (${prefs.email})`));
    } else if (held("email")) {
      await deps.db.tenant(orgId, (tx) => hold(tx, orgId, n.recipient_user_id, n.id, "email", held("email")!));
    } else {
      const { html, text } = layout({
        heading: n.title,
        body: n.body || "Open Nexus for the details.",
        cta: { label: "Open in Nexus", url: `${deps.cfg.publicUrl}${n.link || "/"}` },
        footer: severity === "critical" ? "Critical security notifications are always emailed." : "Change which notifications you get by email in My security → Notifications.",
      });
      const subject = `${severity === "critical" ? "[Critical] " : severity === "warning" ? "[Action needed] " : ""}${n.title}`;
      try {
        await deps.mailer.send({ to: user.email, subject, html, text });
        await deps.db.tenant(orgId, (tx) => record(tx, orgId, n.id, "email", "sent", user.email));
      } catch (err) {
        await deps.db.tenant(orgId, (tx) => record(tx, orgId, n.id, "email", "failed", (err as Error).message.slice(0, 300)));
        throw err; // retry the job; push won't be sent twice
      }
    }
  }
}

export type OrgAlert = { title: string; body: string; severity: Severity; link: string; category: string };

export async function postToSlack(url: string, alert: OrgAlert, publicUrl: string) {
  const icon = alert.severity === "critical" ? ":rotating_light:" : alert.severity === "warning" ? ":warning:" : ":information_source:";
  const link = `${publicUrl}${alert.link || "/"}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      text: `${icon} ${alert.title}`,
      blocks: [
        { type: "section", text: { type: "mrkdwn", text: `${icon} *${alert.title}*${alert.body ? `\n${alert.body}` : ""}` } },
        { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "Open in Nexus" }, url: link }] },
        { type: "context", elements: [{ type: "mrkdwn", text: `Votal Nexus · ${alert.category} · ${alert.severity}` }] },
      ],
    }),
    signal: AbortSignal.timeout(10_000),
    redirect: "error",
  });
  if (!res.ok) throw new Error(`Slack answered HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

export async function deliverSlack(deps: Deps, orgId: string, alert: OrgAlert) {
  const ch = await deps.db.tenant(orgId, (tx) => tx.selectFrom("org_alert_channels").selectAll().where("org_id", "=", orgId).executeTakeFirst());
  if (!ch?.slack_webhook || SEVERITY[alert.severity] < SEVERITY[ch.slack_min_severity]) return;
  const url = deps.sealer.open(ch.slack_webhook, slackAad(orgId)).toString();
  try {
    await assertSafeUrl(url, { allowPrivate: deps.cfg.allowPrivateOutbound });
    await postToSlack(url, alert, deps.cfg.publicUrl);
    await deps.db.tenant(orgId, (tx) => record(tx, orgId, null, "slack", "sent", alert.title.slice(0, 200)));
  } catch (err) {
    await deps.db.tenant(orgId, (tx) => record(tx, orgId, null, "slack", "failed", `${alert.title.slice(0, 100)}: ${networkError(err).slice(0, 200)}`));
    throw err;
  }
}

/**
 * Sends what was held for one user and channel as a single summary: one
 * content-free push for what's still unread, or one email listing everything.
 */
export async function sendSummary(deps: Deps, orgId: string, userId: string, channel: "push" | "email") {
  const ctx = await deps.db.tenant(orgId, async (tx) => {
    const rows = await tx
      .selectFrom("notification_deliveries as d")
      .innerJoin("notifications as n", "n.id", "d.notification_id")
      .select(["d.id as delivery_id", "d.at as held_at", "n.id", "n.title", "n.severity", "n.link", "n.created_at", "n.read_at", "n.archived_at"])
      .where("d.channel", "=", channel)
      .where("d.status", "=", "held")
      .where("n.recipient_user_id", "=", userId)
      .orderBy("n.created_at")
      .execute();
    const user = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", userId).executeTakeFirst();
    const regs = channel === "push" ? await tx.selectFrom("push_registrations").select(["id", "platform", "token"]).where("user_id", "=", userId).execute() : [];
    return { rows, user, regs, prefs: await loadPrefs(tx, userId) };
  });
  const { rows, user, regs, prefs } = ctx;
  if (!rows.length) return;
  const now = new Date();
  // Settings may have changed since this was scheduled: if it should still wait, wait.
  const heldSince = new Date(Math.min(...rows.map((r) => r.held_at.getTime())));
  const due = summaryDue(prefs, channel, heldSince, now);
  if (due.getTime() - now.getTime() > 60_000) {
    await deps.db.tenant(orgId, (tx) => enqueue(tx, orgId, "notify.summary", { user_id: userId, channel }, { runAt: due, dedupeKey: summaryKey(userId, channel), maxAttempts: 4 }));
    return;
  }
  const settle = (ids: string[], status: "sent" | "skipped", detail: string) =>
    ids.length ? deps.db.tenant(orgId, (tx) => tx.updateTable("notification_deliveries").set({ status, detail, at: new Date() }).where("id", "in", ids).execute()) : Promise.resolve();
  const at = hhmm(now, prefs.timezone);

  if (!user || (user.status !== "active" && user.status !== "staged")) return settle(rows.map((r) => r.delivery_id), "skipped", "Account not active");

  if (channel === "push") {
    const unread = rows.filter((r) => !r.read_at && !r.archived_at);
    const seen = rows.filter((r) => r.read_at || r.archived_at);
    await settle(seen.map((r) => r.delivery_id), "skipped", "Already read in Nexus");
    if (!unread.length) return;
    if (!regs.length) return settle(unread.map((r) => r.delivery_id), "skipped", "No phone paired");
    const latest = unread.at(-1)!;
    const title = unread.length === 1 ? "New notification" : `${unread.length} new notifications`;
    const results = await Promise.all(regs.map(async (r) => ({ r, res: await deps.push.send({ platform: r.platform, token: r.token }, { title, category: "notify.summary", id: latest.id, priority: "normal" }) })));
    const ok = results.filter((x) => x.res.ok).length;
    const dead = results.filter((x) => x.res.invalidToken).map((x) => x.r.id);
    if (dead.length) await deps.db.tenant(orgId, (tx) => tx.deleteFrom("push_registrations").where("id", "in", dead).execute());
    if (!ok) throw new Error("No phone accepted the summary push"); // retried; rows stay held
    return settle(unread.map((r) => r.delivery_id), "sent", `In the ${at} summary (${unread.length})`);
  }

  const digest = prefs.digest_enabled;
  const count = `${rows.length} notification${rows.length === 1 ? "" : "s"}`;
  const { html, text } = layout({
    heading: digest ? "Your Nexus digest" : "While you were away",
    body: digest ? `${count} since your last digest.` : `${count} during your quiet hours.`,
    items: rows.map((r) => ({
      title: r.title,
      meta: `${r.severity === "warning" ? "Needs attention · " : ""}${hhmm(r.created_at, prefs.timezone)}`,
      url: `${deps.cfg.publicUrl}${r.link || "/"}`,
    })),
    cta: { label: "Open your inbox", url: `${deps.cfg.publicUrl}/` },
    footer: "Critical security notifications are always sent right away. Change quiet hours and digests in My security → Notifications.",
  });
  await deps.mailer.send({ to: user.email, subject: digest ? `Your Nexus digest: ${count}` : `${count} during quiet hours`, html, text });
  return settle(rows.map((r) => r.delivery_id), "sent", `${digest ? "In the digest" : "In the summary"} at ${at}`);
}

registerJobHandler("notify.summary", async (deps, job) => {
  const p = job.payload as { user_id: string; channel: "push" | "email" };
  await sendSummary(deps, job.org_id, p.user_id, p.channel);
});

registerJobHandler("notify.deliver", async (deps, job) => {
  await deliverNotification(deps, job.org_id, String((job.payload as { notification_id: string }).notification_id));
});
registerJobHandler("notify.slack", async (deps, job) => {
  await deliverSlack(deps, job.org_id, job.payload as unknown as OrgAlert);
});

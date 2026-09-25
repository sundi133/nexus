import type { Deps } from "../context.js";
import { layout } from "../platform/mailer.js";
import { newId } from "../platform/ids.js";
import { registerJobHandler } from "../platform/jobs.js";
import { assertSafeUrl, networkError } from "../platform/outbound.js";
import type { Tx } from "../platform/db.js";

/**
 * Delivers inbox notifications to the recipient's phone and email (NTF-04/06/07)
 * and org-wide alerts to Slack, logging every attempt (NTF-11). Push payloads
 * stay content-free: a generic title and an ID the app resolves over the API.
 * Critical notifications always go out, whatever the preferences.
 */

export const SEVERITY = { info: 0, warning: 1, critical: 2 } as const;
const LEVEL = { all: 0, important: 1, critical: 2 } as const;
export type Severity = keyof typeof SEVERITY;
export type Level = keyof typeof LEVEL;

export const slackAad = (orgId: string) => `org_alert_channels:${orgId}`;

async function record(tx: Tx, orgId: string, notificationId: string | null, channel: "push" | "email" | "slack", status: "sent" | "failed" | "skipped", detail: string) {
  await tx.insertInto("notification_deliveries").values({ id: newId(), org_id: orgId, notification_id: notificationId, channel, status, detail }).execute();
}

export const wants = (level: Level, severity: Severity) => severity === "critical" || SEVERITY[severity] >= LEVEL[level];

export async function deliverNotification(deps: Deps, orgId: string, notificationId: string) {
  const ctx = await deps.db.tenant(orgId, async (tx) => {
    const n = await tx.selectFrom("notifications").selectAll().where("id", "=", notificationId).executeTakeFirst();
    if (!n) return null;
    const user = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", n.recipient_user_id).executeTakeFirst();
    const prefs = await tx.selectFrom("notification_preferences").select(["email", "push"]).where("user_id", "=", n.recipient_user_id).executeTakeFirst();
    const regs = await tx.selectFrom("push_registrations").select(["id", "platform", "token"]).where("user_id", "=", n.recipient_user_id).execute();
    const done = new Set((await tx.selectFrom("notification_deliveries").select("channel").where("notification_id", "=", notificationId).where("status", "in", ["sent", "skipped"]).execute()).map((d) => d.channel));
    return { n, user, prefs: { email: (prefs?.email ?? "important") as Level, push: (prefs?.push ?? "important") as Level }, regs, done };
  });
  if (!ctx?.user || (ctx.user.status !== "active" && ctx.user.status !== "staged")) return;
  const { n, user, prefs, regs, done } = ctx;
  const severity = n.severity as Severity;

  // Push: content-free.
  if (!done.has("push")) {
    if (!wants(prefs.push, severity)) {
      await deps.db.tenant(orgId, (tx) => record(tx, orgId, n.id, "push", "skipped", `Below their push setting (${prefs.push})`));
    } else if (!regs.length) {
      await deps.db.tenant(orgId, (tx) => record(tx, orgId, n.id, "push", "skipped", "No phone paired"));
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

registerJobHandler("notify.deliver", async (deps, job) => {
  await deliverNotification(deps, job.org_id, String((job.payload as { notification_id: string }).notification_id));
});
registerJobHandler("notify.slack", async (deps, job) => {
  await deliverSlack(deps, job.org_id, job.payload as unknown as OrgAlert);
});

import { createHash } from "node:crypto";
import type { Deps } from "../context.js";
import type { Tx } from "../platform/db.js";
import { enqueue, registerJobHandler } from "../platform/jobs.js";
import { networkError } from "../platform/outbound.js";
import { atLeast, type Severity } from "./engine.js";

/**
 * On-call paging (SPEC NTF-10). Alerts at or above an integration's minimum
 * severity trigger a PagerDuty incident (Events API v2) or an Opsgenie alert,
 * keyed by the Nexus alert ID, so acknowledging or resolving in Nexus does the
 * same there — and their webhooks do the same here.
 */

export const oncallAad = (id: string) => `oncall:${id}`;
export const hashToken = (t: string) => createHash("sha256").update(t).digest("hex");

type Integration = { id: string; kind: "pagerduty" | "opsgenie"; name: string; secret: Buffer; region: "us" | "eu"; min_severity: Severity };
type Alert = { id: string; title: string; severity: Severity; rule_name: string; subject: string; count: number; first_seen_at: Date };
export type PageAction = "trigger" | "acknowledge" | "resolve";

const PD_SEVERITY: Record<Severity, string> = { low: "info", medium: "warning", high: "error", critical: "critical" };
const OG_PRIORITY: Record<Severity, string> = { low: "P4", medium: "P3", high: "P2", critical: "P1" };

async function post(url: string, headers: Record<string, string>, body: unknown) {
  let res: Response;
  try {
    res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(10_000), redirect: "error" });
  } catch (e) {
    throw new Error(networkError(e));
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

export async function send(deps: Deps, i: Integration, alert: Alert, action: PageAction, link: string) {
  const key = deps.sealer.open(i.secret, oncallAad(i.id)).toString();
  if (i.kind === "pagerduty") {
    await post(deps.cfg.pagerdutyEventsUrl, {}, {
      routing_key: key,
      event_action: action,
      dedup_key: alert.id,
      ...(action === "trigger"
        ? {
            payload: { summary: alert.title.slice(0, 1024), source: "Votal Nexus", severity: PD_SEVERITY[alert.severity], timestamp: alert.first_seen_at.toISOString(), component: alert.rule_name, custom_details: { subject: alert.subject, count: alert.count } },
            links: [{ href: link, text: "Open in Votal Nexus" }],
          }
        : {}),
    });
    return;
  }
  const base = deps.cfg.opsgenieBase[i.region];
  const headers = { authorization: `GenieKey ${key}` };
  if (action === "trigger") {
    await post(`${base}/v2/alerts`, headers, { message: alert.title.slice(0, 130), alias: alert.id, description: `${alert.rule_name}\n${alert.subject}\n${link}`, priority: OG_PRIORITY[alert.severity], source: "Votal Nexus", tags: ["votal-nexus", alert.severity], details: { link, count: String(alert.count) } });
  } else {
    await post(`${base}/v2/alerts/${encodeURIComponent(alert.id)}/${action === "acknowledge" ? "acknowledge" : "close"}?identifierType=alias`, headers, { source: "Votal Nexus", note: `${action === "acknowledge" ? "Acknowledged" : "Resolved"} in Votal Nexus` });
  }
}

/** Pages (or updates) every integration concerned; failures are recorded on the integration and retried by the job queue. */
registerJobHandler("alerts.page", async (deps, job) => {
  const { alert_id, action, from_integration } = job.payload as { alert_id: string; action: PageAction; from_integration?: string };
  await deps.db.tenant(job.org_id, async (tx) => {
    const alert = await tx.selectFrom("alerts").selectAll().where("id", "=", alert_id).executeTakeFirst();
    if (!alert) return;
    const integrations = await tx.selectFrom("oncall_integrations").selectAll().where("enabled", "=", true).execute();
    const paged = (alert.paged as unknown as string[]) ?? [];
    const targets = integrations.filter((i) => (action === "trigger" ? atLeast(alert.severity, i.min_severity) : paged.includes(i.id)) && i.id !== from_integration);
    const link = `${deps.cfg.publicUrl}/alerts/${alert.id}`;
    let failed: Error | null = null;
    for (const i of targets) {
      try {
        await send(deps, i, alert, action, link);
        await tx.updateTable("oncall_integrations").set({ last_error: "", last_sent_at: new Date() }).where("id", "=", i.id).execute();
        if (action === "trigger" && !paged.includes(i.id)) paged.push(i.id);
      } catch (e) {
        failed = e as Error;
        await tx.updateTable("oncall_integrations").set({ last_error: `${action}: ${(e as Error).message}`.slice(0, 500) }).where("id", "=", i.id).execute();
      }
    }
    await tx.updateTable("alerts").set({ paged: JSON.stringify(paged) }).where("id", "=", alert.id).execute();
    if (failed && action === "trigger" && !paged.length) throw failed; // retry until someone is paged
  });
});

export async function queuePage(tx: Tx, orgId: string, alertId: string, action: PageAction, fromIntegration?: string) {
  await enqueue(tx, orgId, "alerts.page", { alert_id: alertId, action, ...(fromIntegration ? { from_integration: fromIntegration } : {}) });
}

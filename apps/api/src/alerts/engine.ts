import { sql } from "kysely";
import type { Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";
import { enqueue, type JobRunner, registerJobHandler } from "../platform/jobs.js";
import { notifyRoles } from "../notify/send.js";

/**
 * Low-noise alerting (SPEC AUD-08, OPS-08, NTF-09). Rules match audit events
 * and fire when `threshold` matches for the same subject (actor, target, IP or
 * everyone) land within `window_minutes`. While an alert is open it absorbs
 * further matches instead of creating new alerts, so a burst is one alert
 * with a count, and people are told once. Evaluation follows the audit log in
 * commit order with a cursor, like event streaming, so nothing is missed.
 */

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const atLeast = (s: Severity, min: Severity) => SEVERITIES.indexOf(s) >= SEVERITIES.indexOf(min);

export type Match = { types: string[]; outcome?: "success" | "failure" | "denied"; details?: Record<string, string> };
type RuleDef = { key: string; name: string; description: string; severity: Severity; match: Match; group_by: "none" | "actor" | "target" | "ip"; threshold: number; window_minutes: number };

/** Sensible defaults every organization starts with: few, and each worth someone's attention. */
export const BUILTIN_RULES: RuleDef[] = [
  { key: "failed_logins", name: "Repeated failed sign-ins", description: "Someone may be guessing a password.", severity: "high", match: { types: ["auth.login"], outcome: "failure" }, group_by: "actor", threshold: 8, window_minutes: 15 },
  { key: "password_spray", name: "Failed sign-ins from one address", description: "One IP address is failing sign-ins, possibly across many accounts (password spraying).", severity: "high", match: { types: ["auth.login"], outcome: "failure" }, group_by: "ip", threshold: 20, window_minutes: 10 },
  { key: "not_me", name: "Sign-in reported as not me", description: "A person denied a push sign-in they didn't start: their password is probably known to someone else.", severity: "high", match: { types: ["auth.mfa"], outcome: "denied", details: { reason: "not_me" } }, group_by: "actor", threshold: 1, window_minutes: 60 },
  { key: "break_glass", name: "Break-glass account used", description: "An emergency account signed in.", severity: "critical", match: { types: ["auth.break_glass_used"] }, group_by: "actor", threshold: 1, window_minutes: 60 },
  { key: "admin_granted", name: "Admin roles changed", description: "Someone's admin roles changed.", severity: "medium", match: { types: ["user.roles_changed"] }, group_by: "target", threshold: 1, window_minutes: 60 },
  { key: "user_contained", name: "Account contained", description: "An account was contained as possibly compromised.", severity: "high", match: { types: ["user.contain"] }, group_by: "target", threshold: 1, window_minutes: 60 },
  { key: "agent_denied_burst", name: "Agent keeps getting denied", description: "An AI agent is repeatedly calling tools it isn't allowed to: a prompt injection or a broken agent.", severity: "high", match: { types: ["mcp.tool_denied"] }, group_by: "actor", threshold: 5, window_minutes: 1 },
  { key: "mass_offboarding", name: "Many people offboarded", description: "Unusually many offboardings in an hour.", severity: "high", match: { types: ["user.offboarded"] }, group_by: "none", threshold: 5, window_minutes: 60 },
  { key: "device_wipe", name: "Device wipe requested", description: "A device is being erased.", severity: "high", match: { types: ["device.action_requested"], details: { action: "wipe" } }, group_by: "target", threshold: 1, window_minutes: 60 },
  { key: "audit_tamper", name: "Audit log tampering", description: "The audit log failed its integrity check.", severity: "critical", match: { types: ["audit.integrity_failed"] }, group_by: "none", threshold: 1, window_minutes: 1440 },
];

/** Creates the default rules the first time an organization is evaluated or its rules are listed. */
export async function ensureBuiltins(tx: Tx, orgId: string) {
  await tx
    .insertInto("alert_rules")
    .values(BUILTIN_RULES.map((r) => ({ id: newId(), org_id: orgId, builtin_key: r.key, name: r.name, description: r.description, severity: r.severity, match: JSON.stringify(r.match), group_by: r.group_by, threshold: r.threshold, window_minutes: r.window_minutes })))
    .onConflict((oc) => oc.columns(["org_id", "builtin_key"]).doNothing())
    .execute();
}

type Event = { id: string; ts: Date; type: string; outcome: string; actor_id: string | null; actor_display: string; target_id: string | null; target_display: string; ip: string; details: Record<string, unknown>; txid_text: string };

export function matches(m: Match, e: Pick<Event, "type" | "outcome" | "details">): boolean {
  const typeOk = m.types.some((t) => (t.endsWith("*") ? e.type.startsWith(t.slice(0, -1)) : e.type === t));
  if (!typeOk) return false;
  if (m.outcome && e.outcome !== m.outcome) return false;
  for (const [k, v] of Object.entries(m.details ?? {})) if (String(e.details?.[k] ?? "") !== v) return false;
  return true;
}

export function groupOf(by: "none" | "actor" | "target" | "ip", e: Event): { key: string; subject: string } | null {
  switch (by) {
    case "none":
      return { key: "*", subject: "" };
    case "actor":
      return e.actor_id || e.actor_display ? { key: e.actor_id ?? e.actor_display, subject: e.actor_display || e.actor_id! } : null;
    case "target":
      return e.target_id || e.target_display ? { key: e.target_id ?? e.target_display, subject: e.target_display || e.target_id! } : null;
    case "ip":
      return e.ip ? { key: e.ip, subject: e.ip } : null;
  }
}

const SYSTEM: RequestMeta = { ip: "", userAgent: "nexus-alerts", requestId: "" };

/** Evaluates new audit events against the organization's rules. Returns the alerts opened. */
export async function evaluate(deps: Deps, orgId: string, meta: RequestMeta = SYSTEM): Promise<string[]> {
  return deps.db.tenant(orgId, async (tx) => {
    await sql`SELECT pg_advisory_xact_lock(hashtext('alerts:' || ${orgId}))`.execute(tx);
    await ensureBuiltins(tx, orgId);
    const cur = await tx.selectFrom("alert_cursors").selectAll().executeTakeFirst();
    if (!cur) {
      // First run: start from now. History isn't alerted on.
      const head = (await sql<{ txid: string; id: string }>`SELECT txid::text AS txid, id FROM audit_events ORDER BY txid DESC, id DESC LIMIT 1`.execute(tx)).rows[0];
      await tx.insertInto("alert_cursors").values({ org_id: orgId, cursor_txid: head?.txid ?? "0", cursor_id: head?.id ?? "00000000-0000-0000-0000-000000000000" }).execute();
      return [];
    }
    const events = (
      await sql<Event>`
        SELECT e.id, e.ts, e.type, e.outcome, e.actor_id, e.actor_display, e.target_id, e.target_display, e.ip, e.details, e.txid::text AS txid_text
        FROM audit_events e
        WHERE (e.txid, e.id) > (${cur.cursor_txid}::xid8, ${cur.cursor_id}::uuid) AND e.txid < pg_snapshot_xmin(pg_current_snapshot())
        ORDER BY e.txid, e.id LIMIT 2000`.execute(tx)
    ).rows;
    if (!events.length) return [];
    const rules = await tx.selectFrom("alert_rules").selectAll().where("enabled", "=", true).execute();
    const opened: string[] = [];
    for (const e of events) {
      if (e.type.startsWith("alert.")) continue; // never alert on alerting itself
      for (const r of rules) {
        const m = r.match as unknown as Match;
        if (!matches(m, e)) continue;
        const g = groupOf(r.group_by, e);
        if (!g) continue;
        const active = await tx.selectFrom("alerts").select(["id"]).where("rule_id", "=", r.id).where("group_key", "=", g.key).where("status", "<>", "resolved").executeTakeFirst();
        if (active) {
          // Deduplicated: the open alert grows; nobody is told again.
          await sql`UPDATE alerts SET count = count + 1, last_seen_at = greatest(last_seen_at, ${e.ts}), event_ids = (array_prepend(${e.id}::uuid, event_ids))[1:100] WHERE id = ${active.id}`.execute(tx);
          continue;
        }
        await tx.insertInto("alert_hits").values({ org_id: orgId, rule_id: r.id, group_key: g.key, event_id: e.id, at: e.ts }).onConflict((oc) => oc.doNothing()).execute();
        const inWindow = await tx
          .selectFrom("alert_hits")
          .select(["event_id", "at"])
          .where("rule_id", "=", r.id)
          .where("group_key", "=", g.key)
          .where("at", ">", new Date(e.ts.getTime() - r.window_minutes * 60_000))
          .orderBy("at", "desc")
          .execute();
        if (inWindow.length < r.threshold) continue;
        const id = newId();
        // The count lives on the alert (it keeps growing); the title stays true.
        const title = `${r.name}${g.subject ? `: ${g.subject}` : ""}`;
        await tx
          .insertInto("alerts")
          .values({
            id,
            org_id: orgId,
            rule_id: r.id,
            rule_name: r.name,
            group_key: g.key,
            subject: g.subject,
            title: title.slice(0, 300),
            severity: r.severity,
            count: inWindow.length,
            event_ids: inWindow.slice(0, 100).map((h) => h.event_id),
            first_seen_at: inWindow[inWindow.length - 1]!.at,
            last_seen_at: e.ts,
            paged: JSON.stringify([]),
          })
          .execute();
        await tx.deleteFrom("alert_hits").where("rule_id", "=", r.id).where("group_key", "=", g.key).execute();
        await audit(tx, orgId, { meta }, { type: "alert.opened", actor: { type: "system", id: null, display: "Alerting" }, target: { type: "alert", id, display: title }, details: { rule_id: r.id, severity: r.severity, count: inWindow.length } });
        await notifyRoles(tx, orgId, ["owner", "admin", "security_analyst"], {
          category: "security.alert",
          severity: r.severity === "critical" ? "critical" : r.severity === "high" ? "warning" : "info",
          title,
          body: r.description,
          entity: { type: "alert", id },
          link: `/alerts/${id}`,
        });
        await enqueue(tx, orgId, "alerts.page", { alert_id: id, action: "trigger" });
        opened.push(id);
      }
    }
    const last = events[events.length - 1]!;
    await tx.updateTable("alert_cursors").set({ cursor_txid: last.txid_text, cursor_id: last.id }).execute();
    await tx.deleteFrom("alert_hits").where("at", "<", new Date(Date.now() - 25 * 60 * 60_000)).execute();
    return opened;
  });
}

registerJobHandler("alerts.evaluate", async (deps, job) => {
  await evaluate(deps, job.org_id, { ...SYSTEM, requestId: job.id });
});

/** Every tick (a few seconds): organizations with new events are evaluated. */
export function scheduleAlerts(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 10_000) return;
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_alerts_due()`.execute(tx)).rows);
    for (const d of due) await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, "alerts.evaluate", {}, { dedupeKey: "alerts.evaluate" }));
  });
}

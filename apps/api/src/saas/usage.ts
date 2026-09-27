import { sql } from "kysely";
import type { Tx } from "../platform/db.js";
import { SAAS_BY_KEY } from "./catalog.js";

type SaasEvent = { at: string; kind: string; action: string; app: string; count: number };

/** Unapproved apps and what browsers do about them (approved and unreviewed apps are allowed). */
export async function saasDecisions(tx: Tx) {
  const rows = await tx.selectFrom("saas_apps").select(["app_key", "action"]).where("status", "=", "unapproved").execute();
  return new Map(rows.filter((r) => SAAS_BY_KEY.has(r.app_key)).map((r) => [r.app_key, r.action]));
}

/**
 * Adds a browser's SaaS counts to the day's totals. Visits and password sign-ins count only while
 * discovery is on; blocked visits (the organization's own rule at work) always do.
 */
export async function recordSaasEvents(tx: Tx, orgId: string, who: { email: string; userId: string | null; discovery: boolean }, events: SaasEvent[]) {
  const totals = new Map<string, { app: string; day: string; visits: number; logins: number; blocked: number; last: Date }>();
  const now = Date.now();
  for (const e of events) {
    if (!SAAS_BY_KEY.has(e.app)) continue;
    const at = new Date(e.at);
    // Late batches are fine for a week; clocks far in the future aren't trusted.
    if (!(at.getTime() > now - 7 * 86_400_000 && at.getTime() < now + 86_400_000)) continue;
    const visits = e.kind === "saas" && who.discovery ? e.count : 0;
    const logins = e.kind === "saas_login" && who.discovery ? e.count : 0;
    const blocked = e.kind === "visit" && e.action === "blocked" ? e.count : 0;
    if (!visits && !logins && !blocked) continue;
    const day = at.toISOString().slice(0, 10);
    const k = `${e.app}|${day}`;
    const t = totals.get(k) ?? { app: e.app, day, visits: 0, logins: 0, blocked: 0, last: at };
    t.visits += visits;
    t.logins += logins;
    t.blocked += blocked;
    if (at > t.last) t.last = at;
    totals.set(k, t);
  }
  for (const t of totals.values()) {
    await tx
      .insertInto("saas_usage")
      .values({ org_id: orgId, app_key: t.app, user_email: who.email, user_id: who.userId, day: t.day, visits: t.visits, password_logins: t.logins, blocked: t.blocked, last_at: t.last })
      .onConflict((oc) =>
        oc.columns(["org_id", "app_key", "user_email", "day"]).doUpdateSet({
          visits: sql`saas_usage.visits + excluded.visits`,
          password_logins: sql`saas_usage.password_logins + excluded.password_logins`,
          blocked: sql`saas_usage.blocked + excluded.blocked`,
          last_at: sql`greatest(saas_usage.last_at, excluded.last_at)`,
          user_id: sql`coalesce(excluded.user_id, saas_usage.user_id)`,
        }),
      )
      .execute();
  }
}

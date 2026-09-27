import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Deps } from "../context.js";
import { requirePermission } from "../auth/guard.js";
import { RETENTION_DAYS as PROCESS_EVENT_DAYS } from "../devices/process-events.js";
import type { JobRunner } from "../platform/jobs.js";
import { bearer, json, problemResponses } from "../schemas.js";

/**
 * What Nexus keeps, and for how long. The fixed rules live in nexus_apply_retention()
 * (migration 0048) and run hourly; this list describes them, plus the ones pruned elsewhere.
 */
export const RETENTION = [
  { key: "audit_events", name: "Audit log", kept: "Your setting (default 365 days; 30 days to 10 years)", notes: "Append-only and hash-chained; never deleted before it's delivered to your SIEM or archive" },
  { key: "device_process_events", name: "Process events from devices", kept: `${PROCESS_EVENT_DAYS} days`, notes: "Only collected when turned on" },
  { key: "sessions", name: "Sessions (IP address, browser)", kept: "30 days after they end", notes: "For investigating sign-ins" },
  { key: "invitations", name: "Invitations", kept: "30 days after they're accepted, revoked or expire", notes: "" },
  { key: "notifications", name: "Notification inbox", kept: "180 days", notes: "" },
  { key: "notification_deliveries", name: "Notification delivery log", kept: "90 days", notes: "" },
  { key: "event_deliveries", name: "SIEM and webhook delivery log", kept: "30 days", notes: "The events themselves are the audit log" },
  { key: "alert_hits", name: "Alert rule matches", kept: "90 days", notes: "Alerts themselves are kept" },
  { key: "enforcement_events", name: "Block rule events from devices", kept: "90 days", notes: "" },
  { key: "device_commands", name: "Device commands (lock, restart…)", kept: "90 days after they finish", notes: "Each is also in the audit log" },
  { key: "live_queries", name: "Live device queries and results", kept: "30 days after they expire", notes: "" },
  { key: "sign_in_artifacts", name: "Sign-in codes and challenges", kept: "1 day after they expire", notes: "OIDC codes, MFA and passkey challenges, password reset links, pairing codes" },
  { key: "jobs", name: "Background job records", kept: "7 days (30 days if they failed)", notes: "" },
  { key: "everything_else", name: "Everything else (people, groups, apps, devices, policies…)", kept: "Until you delete it, or the organization", notes: "Erase a person under Users; delete the organization under Settings" },
] as const;

const Retention = z
  .object({
    audit_retention_days: z.number().int(),
    classes: z.array(z.object({ key: z.string(), name: z.string(), kept: z.string(), notes: z.string() })),
  })
  .openapi("DataRetention");

export function registerRetentionRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/org/data-retention",
      tags: ["Data"],
      summary: "What Nexus keeps about the organization, and for how long",
      security: bearer,
      responses: { 200: json(Retention), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const days = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const o = await tx.selectFrom("organizations").select("settings").where("id", "=", p.orgId).executeTakeFirstOrThrow();
        return Number((o.settings as { audit_retention_days?: number } | null)?.audit_retention_days ?? 365);
      });
      return c.json({ audit_retention_days: days, classes: RETENTION.map((r) => ({ ...r })) }, 200);
    },
  );
}

/** Applies the retention rules (one batch per rule). Returns what was deleted, by rule. */
export async function applyRetention(deps: Deps, batch = 10_000) {
  const rows = await deps.db.unscoped(async (tx) => (await sql<{ data: string; deleted: number }>`SELECT * FROM nexus_apply_retention(${batch})`.execute(tx)).rows);
  return Object.fromEntries(rows.map((r) => [r.data, Number(r.deleted)]));
}

export function scheduleRetention(jobs: JobRunner, deps: Deps) {
  jobs.every("data.retention", 60 * 60_000, async () => {
    const deleted = await applyRetention(deps);
    const total = Object.values(deleted).reduce((a, b) => a + b, 0);
    if (total) console.log(JSON.stringify({ level: "info", msg: "retention applied", deleted }));
  });
}

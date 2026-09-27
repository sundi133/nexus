import { sql } from "kysely";
import type { Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { getSettings } from "../org/settings.js";
import type { Tx } from "../platform/db.js";
import type { JobRunner } from "../platform/jobs.js";

/**
 * Device health for alerting (docs/DEVICE-HEALTH.md): a device going quiet, and its disk filling up.
 * Each is a state with a start, so an episode is recorded once (an audit event the alert rules
 * match) and again when it ends. Compliance changes are recorded where they're evaluated.
 */

const HYSTERESIS = 2; // points of free space above the limit before "disk low" clears

type Disk = { mount: string; size_bytes: number; free_bytes?: number };

/** The fullest disk that reports free space, as a percentage free. */
export function lowestFree(disks: Disk[] | undefined) {
  let worst: { mount: string; free_percent: number; free_gb: number } | null = null;
  for (const d of disks ?? []) {
    if (d.free_bytes === undefined || !d.size_bytes) continue;
    const pct = (d.free_bytes / d.size_bytes) * 100;
    if (!worst || pct < worst.free_percent) worst = { mount: d.mount, free_percent: Math.round(pct * 10) / 10, free_gb: Math.round((d.free_bytes / 1e9) * 10) / 10 };
  }
  return worst;
}

/** On each check-in: back online, and the disk. */
export async function checkinHealth(tx: Tx, d: { id: string; org_id: string; hostname: string }, disks: Disk[] | undefined, meta: RequestMeta) {
  const cur = await tx.selectFrom("devices").select(["offline_since", "disk_low_since"]).where("id", "=", d.id).executeTakeFirstOrThrow();
  const actor = { type: "system" as const, id: null, display: d.hostname };
  const target = { type: "device", id: d.id, display: d.hostname };
  if (cur.offline_since) {
    await tx.updateTable("devices").set({ offline_since: null }).where("id", "=", d.id).execute();
    await audit(tx, d.org_id, { meta }, { type: "device.back_online", actor, target, details: { offline_since: cur.offline_since.toISOString() } });
  }
  const disk = lowestFree(disks);
  if (!disk) return;
  const { disk_low_percent: limit } = await getSettings(tx, d.org_id);
  if (!cur.disk_low_since && disk.free_percent < limit) {
    await tx.updateTable("devices").set({ disk_low_since: new Date() }).where("id", "=", d.id).execute();
    await audit(tx, d.org_id, { meta }, { type: "device.disk_low", outcome: "failure", actor, target, details: { mount: disk.mount, free_percent: disk.free_percent, free_gb: disk.free_gb, limit_percent: limit } });
  } else if (cur.disk_low_since && disk.free_percent >= limit + HYSTERESIS) {
    await tx.updateTable("devices").set({ disk_low_since: null }).where("id", "=", d.id).execute();
    await audit(tx, d.org_id, { meta }, { type: "device.disk_ok", actor, target, details: { mount: disk.mount, free_percent: disk.free_percent, free_gb: disk.free_gb } });
  }
}

/** Devices that stopped checking in for longer than the organization's limit. */
export async function markOffline(tx: Tx, orgId: string, meta: RequestMeta) {
  const { device_offline_hours: hours } = await getSettings(tx, orgId);
  const rows = await tx
    .updateTable("devices")
    .set({ offline_since: sql`now()` })
    .where("status", "=", "active")
    .where("offline_since", "is", null)
    .where("last_seen_at", "<", sql<Date>`now() - make_interval(hours => ${hours})`)
    .returning(["id", "hostname", "last_seen_at"])
    .execute();
  for (const r of rows) {
    await audit(tx, orgId, { meta }, {
      type: "device.went_offline",
      actor: { type: "system", id: null, display: "Nexus" },
      target: { type: "device", id: r.id, display: r.hostname },
      details: { last_seen_at: r.last_seen_at?.toISOString() ?? null, limit_hours: hours },
    });
  }
  return rows.length;
}

export function scheduleDeviceHealth(jobs: JobRunner, deps: Deps) {
  jobs.every("devices.health", 5 * 60_000, async () => {
    const orgs = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_orgs_with_quiet_devices()`.execute(tx)).rows);
    for (const o of orgs) await deps.db.tenant(o.org_id, (tx) => markOffline(tx, o.org_id, { ip: "", userAgent: "nexus-scheduler", requestId: "" }));
  });
}

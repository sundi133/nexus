import { createHash } from "node:crypto";
import { sql } from "kysely";
import type { Principal, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { notifyRoles } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";
import { compareVersions, GOOS, type AgentRelease, type ReleaseStore } from "./releases.js";

/**
 * Staged agent rollouts (DEV-07): canary devices → 10% of the fleet → all.
 * Each stage waits `advance_after_hours` and needs at least one healthy
 * update; any failure or agent-side rollback halts the rollout and alerts
 * admins. Agents also roll themselves back (internal/update), so a halt means
 * "stop spreading", never "devices are broken".
 */

export const STAGES = ["canary", "early", "all"] as const;
export type Stage = (typeof STAGES)[number];
export const EARLY_PERCENT = 10;
const ACTIVE_WINDOW_MS = 7 * 24 * 3600_000; // devices silent longer than this don't block completion

/** Stable 0–99 bucket per device, so the same machines are "early" every time. */
export const bucket = (deviceId: string) => createHash("sha256").update(deviceId).digest().readUInt32BE(0) % 100;

type Rollout = {
  id: string;
  org_id: string;
  version: string;
  stage: Stage;
  status: "active" | "paused" | "halted" | "completed" | "cancelled";
  canary_device_ids: string[];
  stage_started_at: Date;
  failures_since: Date;
  halted_reason: string;
  created_by: string | null;
  created_at: Date;
};

export type FleetDevice = { id: string; hostname: string; platform: string; arch: string; agent_version: string; last_seen_at: Date | null };

export function ringOf(r: Pick<Rollout, "canary_device_ids">, deviceId: string): Stage {
  if (r.canary_device_ids.includes(deviceId)) return "canary";
  return bucket(deviceId) < EARLY_PERCENT ? "early" : "all";
}
export const inStage = (r: Pick<Rollout, "canary_device_ids" | "stage">, deviceId: string) =>
  STAGES.indexOf(ringOf(r, deviceId)) <= STAGES.indexOf(r.stage);

export async function getSettings(tx: Tx) {
  const s = await tx.selectFrom("agent_update_settings").selectAll().executeTakeFirst();
  return { auto_rollout: s?.auto_rollout ?? true, advance_after_hours: s?.advance_after_hours ?? 24 };
}

export async function openRollout(tx: Tx): Promise<Rollout | null> {
  return ((await tx.selectFrom("agent_rollouts").selectAll().where("status", "in", ["active", "paused", "halted"]).executeTakeFirst()) as Rollout | undefined) ?? null;
}

export async function fleet(tx: Tx): Promise<FleetDevice[]> {
  return tx.selectFrom("devices").select(["id", "hostname", "platform", "arch", "agent_version", "last_seen_at"]).where("status", "=", "active").execute();
}

export const supports = (rel: AgentRelease, d: Pick<FleetDevice, "platform" | "arch">) => rel.artifacts.find((a) => a.os === GOOS[d.platform] && a.arch === d.arch) ?? null;

/** Canaries: the admin's choice, else ~1% of the fleet (at least one), preferring recently seen devices. */
async function pickCanaries(tx: Tx, rel: AgentRelease, explicit: string[] | undefined) {
  const devices = (await fleet(tx)).filter((d) => supports(rel, d));
  if (explicit?.length) {
    const known = new Set(devices.map((d) => d.id));
    const missing = explicit.filter((id) => !known.has(id));
    if (missing.length) throw new Error(`Not an active device this release supports: ${missing.join(", ")}`);
    return explicit;
  }
  const hour = Date.now() - 3600_000;
  const n = Math.max(1, Math.ceil(devices.length / 100));
  return devices
    .sort((a, b) => Number((b.last_seen_at?.getTime() ?? 0) > hour) - Number((a.last_seen_at?.getTime() ?? 0) > hour) || bucket(a.id) - bucket(b.id))
    .slice(0, n)
    .map((d) => d.id);
}

type Who = { principal?: Principal; meta: RequestMeta };
const system = { type: "system" as const, id: null, display: "Nexus" };

export async function startRollout(tx: Tx, orgId: string, rel: AgentRelease, who: Who, canaries?: string[]) {
  const current = await openRollout(tx);
  if (current) {
    await tx.updateTable("agent_rollouts").set({ status: "cancelled", updated_at: new Date() }).where("id", "=", current.id).execute();
    await audit(tx, orgId, who, { type: "agent.rollout_cancelled", target: { type: "agent_rollout", id: current.id, display: current.version }, details: { reason: `superseded by ${rel.version}` }, ...(who.principal ? {} : { actor: system }) });
  }
  const id = newId();
  const canary_device_ids = await pickCanaries(tx, rel, canaries);
  await tx.insertInto("agent_rollouts").values({ id, org_id: orgId, version: rel.version, canary_device_ids, created_by: who.principal?.userId ?? null }).execute();
  await audit(tx, orgId, who, {
    type: "agent.rollout_started",
    target: { type: "agent_rollout", id, display: rel.version },
    details: { version: rel.version, canary_device_ids },
    ...(who.principal ? {} : { actor: system }),
  });
  return id;
}

/** With auto-rollout on, a newly published release starts rolling out by itself (once). */
export async function ensureAutoRollout(tx: Tx, orgId: string, store: ReleaseStore, meta: RequestMeta) {
  const settings = await getSettings(tx);
  if (!settings.auto_rollout) return;
  const latest = await store.latest();
  if (!latest) return;
  const open = await openRollout(tx);
  if (open && compareVersions(open.version, latest.version) >= 0) return;
  const seen = await tx.selectFrom("agent_rollouts").select("id").where("version", "=", latest.version).executeTakeFirst();
  if (seen) return; // an admin cancelled or finished it: don't restart it behind their back
  if (!(await fleet(tx)).some((d) => supports(latest, d) && compareVersions(d.agent_version, latest.version) < 0)) return;
  // Concurrent check-ins may all get here: let one start it, the others re-check.
  await sql`SELECT pg_advisory_xact_lock(hashtextextended(${orgId + ":agent-rollout"}, 0))`.execute(tx);
  if (await tx.selectFrom("agent_rollouts").select("id").where("version", "=", latest.version).executeTakeFirst()) return;
  await startRollout(tx, orgId, latest, { meta });
}

/**
 * Advances, halts or completes the open rollout based on what devices have
 * reported. Runs lazily (check-ins, admin views) — cheap queries on small tables.
 */
export async function evaluateRollout(tx: Tx, orgId: string, store: ReleaseStore, meta: RequestMeta, now = new Date()): Promise<Rollout | null> {
  const r = await openRollout(tx);
  if (!r || r.status === "paused") return r;

  if (r.status === "active") {
    const failure = await tx
      .selectFrom("device_updates")
      .innerJoin("devices", "devices.id", "device_updates.device_id")
      .select(["devices.hostname", "device_updates.state", "device_updates.error", "device_updates.device_id"])
      .where("device_updates.version", "=", r.version)
      .where("device_updates.state", "in", ["failed", "rolled_back"])
      .where("device_updates.updated_at", ">=", r.failures_since)
      .orderBy("device_updates.updated_at")
      .executeTakeFirst();
    if (failure) {
      const reason = `${failure.hostname} ${failure.state === "rolled_back" ? "rolled back" : "failed to install"} ${r.version}: ${failure.error || "no details"}`;
      const halted = await tx.updateTable("agent_rollouts").set({ status: "halted", halted_reason: reason, updated_at: now }).where("id", "=", r.id).where("status", "=", "active").executeTakeFirst();
      if (halted.numUpdatedRows === 0n) return { ...r, status: "halted", halted_reason: reason }; // another check-in got here first
      await audit(tx, orgId, { meta }, { type: "agent.rollout_halted", outcome: "failure", actor: system, target: { type: "agent_rollout", id: r.id, display: r.version }, details: { reason, device_id: failure.device_id } });
      await notifyRoles(tx, orgId, ["owner", "admin"], {
        category: "devices.agent_rollout",
        severity: "warning",
        title: `Agent ${r.version} rollout halted`,
        body: `${reason}. No more devices will be offered this version until you resume it. The device kept its previous version and is still working.`,
        entity: { type: "agent_rollout", id: r.id },
        link: "/agent-updates",
      });
      return { ...r, status: "halted", halted_reason: reason };
    }
  }
  if (r.status !== "active") return r;

  const devices = await fleet(tx);
  const settings = await getSettings(tx);
  if (r.stage !== "all" && settings.advance_after_hours > 0 && now.getTime() - r.stage_started_at.getTime() >= settings.advance_after_hours * 3600_000) {
    const healthy = devices.some((d) => inStage(r, d.id) && compareVersions(d.agent_version, r.version) >= 0);
    if (healthy) return advance(tx, orgId, r, { meta }, now);
  }
  if (r.stage === "all") {
    const rel = await store.get(r.version);
    const active = now.getTime() - ACTIVE_WINDOW_MS;
    const updatedRows = await tx.selectFrom("device_updates").select("device_id").where("version", "=", r.version).where("state", "in", ["failed", "rolled_back"]).execute();
    const failed = new Set(updatedRows.map((u) => u.device_id));
    // Devices with no build in this release, long silent, or that gave up on it can't hold it open.
    const remaining = devices.filter(
      (d) => rel && supports(rel, d) && (d.last_seen_at?.getTime() ?? 0) > active && compareVersions(d.agent_version, r.version) < 0 && !failed.has(d.id),
    );
    if (remaining.length === 0) {
      const done = await tx.updateTable("agent_rollouts").set({ status: "completed", updated_at: now }).where("id", "=", r.id).where("status", "=", "active").executeTakeFirst();
      if (done.numUpdatedRows > 0n) await audit(tx, orgId, { meta }, { type: "agent.rollout_completed", actor: system, target: { type: "agent_rollout", id: r.id, display: r.version } });
      return { ...r, status: "completed" };
    }
  }
  return r;
}

export async function advance(tx: Tx, orgId: string, r: Rollout, who: Who, now = new Date()): Promise<Rollout> {
  const next = STAGES[STAGES.indexOf(r.stage) + 1];
  if (!next) return r;
  const moved = await tx.updateTable("agent_rollouts").set({ stage: next, stage_started_at: now, updated_at: now }).where("id", "=", r.id).where("stage", "=", r.stage).executeTakeFirst();
  if (moved.numUpdatedRows === 0n) return { ...r, stage: next, stage_started_at: now };
  await audit(tx, orgId, who, {
    type: "agent.rollout_advanced",
    target: { type: "agent_rollout", id: r.id, display: r.version },
    details: { from: r.stage, to: next },
    ...(who.principal ? {} : { actor: system }),
  });
  return { ...r, stage: next, stage_started_at: now };
}

/** The update to offer a device in its check-in, if any. */
export async function offerFor(tx: Tx, orgId: string, d: FleetDevice, store: ReleaseStore, meta: RequestMeta) {
  await ensureAutoRollout(tx, orgId, store, meta);
  const r = await evaluateRollout(tx, orgId, store, meta);
  if (!r || r.status !== "active" || !inStage(r, d.id) || compareVersions(d.agent_version, r.version) >= 0) return null;
  const rel = await store.get(r.version);
  const a = rel && supports(rel, d);
  if (!a) return null;
  const prior = await tx.selectFrom("device_updates").select("state").where("device_id", "=", d.id).where("version", "=", r.version).executeTakeFirst();
  if (prior && (prior.state === "failed" || prior.state === "rolled_back")) return null; // never retry a version that failed here
  if (!prior) await tx.insertInto("device_updates").values({ org_id: orgId, device_id: d.id, version: r.version, state: "offered", from_version: d.agent_version }).execute();
  return { version: r.version, url: `/v1/agent/releases/${r.version}/${a.file}`, sha256: a.sha256, size: a.size, key_id: a.key_id, signature: a.signature };
}

export type UpdateResult = { version: string; state: "installed" | "failed" | "rolled_back"; error?: string };

/** An agent reports how an update went (in its check-in). */
export async function recordResult(tx: Tx, orgId: string, d: Pick<FleetDevice, "id" | "hostname" | "agent_version">, res: UpdateResult, meta: RequestMeta) {
  await tx
    .insertInto("device_updates")
    .values({ org_id: orgId, device_id: d.id, version: res.version, state: res.state, error: res.error ?? "", from_version: "" })
    .onConflict((oc) => oc.columns(["device_id", "version"]).doUpdateSet({ state: res.state, error: res.error ?? "", updated_at: sql`now()` }))
    .execute();
  const ok = res.state === "installed";
  await audit(tx, orgId, { meta, display: d.hostname }, {
    type: ok ? "device.agent_updated" : "device.agent_update_failed",
    outcome: ok ? "success" : "failure",
    actor: { type: "system", id: null, display: d.hostname },
    target: { type: "device", id: d.id, display: d.hostname },
    details: { version: res.version, state: res.state, ...(res.error ? { error: res.error } : {}), running: d.agent_version },
  });
}

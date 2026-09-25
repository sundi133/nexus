import { sql } from "kysely";
import type { Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { notifyUsers } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { enqueue, registerJobHandler, type JobRunner } from "../platform/jobs.js";
import type { Compliance, DevicePlatform } from "../platform/db-types.js";
import { mdmContext } from "./mdm-signals.js";
import { CHECK_INFO, CHECK_KEYS, DEFAULT_POLICIES, enforce, evaluate, PostureFacts, type CheckKey, type Policy } from "./posture.js";

export const ONLINE_WINDOW_MS = 3 * 60_000;
export const CHECKIN_INTERVAL_S = 60;
export const INVENTORY_INTERVAL_S = 900;

/** The org's policies: stored rows over defaults, in a stable order. */
export async function getPolicies(tx: Tx): Promise<Policy[]> {
  const rows = await tx.selectFrom("device_policies").selectAll().execute();
  return DEFAULT_POLICIES.map((d) => {
    const r = rows.find((x) => x.check_key === d.key);
    return r ? { key: d.key, enabled: r.enabled, params: { ...d.params, ...(r.params as object) }, mode: r.mode, grace_hours: r.grace_hours } : d;
  }).filter((p) => (CHECK_KEYS as readonly string[]).includes(p.key)) as Policy[];
}

type DeviceForEval = { id: string; org_id: string; hostname: string; platform: DevicePlatform; os_version: string; serial?: string; posture: unknown; compliance: Compliance; primary_user_id: string | null; compliance_grace_until?: Date | null };
export const EVAL_COLUMNS = ["id", "org_id", "hostname", "platform", "os_version", "serial", "posture", "compliance", "primary_user_id", "compliance_grace_until"] as const;

/**
 * Re-evaluates a device against the org's policies, stores per-check results,
 * and on a compliance change records it and tells the people who should act.
 */
export async function evaluateDevice(tx: Tx, device: DeviceForEval, policies: Policy[], who: { meta: RequestMeta }) {
  // One evaluation of a device at a time (check-ins, policy changes and MDM syncs can overlap).
  // NO KEY UPDATE: serializes evaluations without conflicting with the KEY SHARE locks foreign keys take (e.g. MDM links).
  await tx.selectFrom("devices").select("id").where("id", "=", device.id).forNoKeyUpdate().execute();
  const facts = PostureFacts.safeParse(device.posture).data ?? null;
  const previous = new Map(
    (await tx.selectFrom("device_checks").select(["check_key", "status", "failing_since"]).where("device_id", "=", device.id).execute()).map((c) => [c.check_key, c]),
  );
  const { checks: results, compliance, grace_until } = enforce(evaluate(device, facts, policies, await mdmContext(tx, device)), policies, previous);

  await tx.deleteFrom("device_checks").where("device_id", "=", device.id).execute();
  if (results.length) {
    await tx
      .insertInto("device_checks")
      .values(
        results.map((r) => ({
          org_id: device.org_id,
          device_id: device.id,
          check_key: r.key,
          status: r.status,
          detail: r.detail,
          enforced: r.enforced,
          failing_since: r.failing_since,
          grace_until: r.grace_until,
          updated_at: new Date(),
        })),
      )
      .execute();
  }
  if ((device.compliance_grace_until?.getTime() ?? null) !== (grace_until?.getTime() ?? null)) {
    await tx.updateTable("devices").set({ compliance_grace_until: grace_until }).where("id", "=", device.id).execute();
  }
  // A newly failing enforced check with a grace period: tell the user what to fix, and by when.
  const newlyInGrace = results.filter((r) => r.grace_until && previous.get(r.key)?.status !== "fail");
  if (newlyInGrace.length && device.primary_user_id) {
    const by = new Date(Math.min(...newlyInGrace.map((r) => r.grace_until!.getTime())));
    await notifyUsers(tx, device.org_id, [device.primary_user_id], {
      category: "device.grace",
      severity: "warning",
      title: `Fix ${newlyInGrace.map((r) => CHECK_INFO[r.key as CheckKey].title.toLowerCase()).join(" and ")} on ${device.hostname} by ${by.toUTCString().slice(0, 22)} UTC`,
      body: `${newlyInGrace.map((r) => r.detail).join(" · ")}. After that, this device won't meet your organization's policy and apps may stop letting it sign in.`,
      entity: { type: "device", id: device.id },
      link: "/my-devices",
    });
  }
  if (compliance !== device.compliance) {
    await tx.updateTable("devices").set({ compliance, compliance_changed_at: new Date() }).where("id", "=", device.id).execute();
    const failing = results.filter((r) => r.status === "fail" && r.enforced && !r.grace_until);
    await audit(tx, device.org_id, { meta: who.meta }, {
      type: "device.compliance_changed",
      actor: { type: "system", id: null, display: "Nexus" },
      target: { type: "device", id: device.id, display: device.hostname },
      details: { from: device.compliance, to: compliance, failing: failing.map((f) => ({ check: f.key, detail: f.detail })) },
    });
    if (compliance === "non_compliant") {
      if (device.primary_user_id) {
        await notifyUsers(tx, device.org_id, [device.primary_user_id], {
          category: "device.noncompliant",
          severity: "warning",
          title: `${device.hostname} needs attention`,
          body: failing.map((f) => f.detail).join(" · "),
          entity: { type: "device", id: device.id },
          link: "/my-devices",
        });
      }
    } else if (compliance === "compliant" && device.compliance === "non_compliant" && device.primary_user_id) {
      await notifyUsers(tx, device.org_id, [device.primary_user_id], {
        category: "device.compliant",
        title: `${device.hostname} is compliant again`,
        entity: { type: "device", id: device.id },
        link: "/my-devices",
      });
    }
  }
  return { compliance, results };
}

/** After a policy change, every active device is re-evaluated right away. */
export async function reevaluateAll(tx: Tx, who: { meta: RequestMeta }) {
  const policies = await getPolicies(tx);
  const devices = await tx
    .selectFrom("devices")
    .select([...EVAL_COLUMNS])
    .where("status", "=", "active")
    .orderBy("id") // the same lock order everywhere, so concurrent re-evaluations queue instead of deadlocking
    .forNoKeyUpdate()
    .execute();
  let changed = 0;
  for (const d of devices) {
    const r = await evaluateDevice(tx, d, policies, who);
    if (r.compliance !== d.compliance) changed++;
  }
  return { devices: devices.length, changed };
}

const SCHEDULER_META: RequestMeta = { ip: "", userAgent: "nexus-scheduler", requestId: "" };

/** Re-evaluates one device (the `device.reevaluate` job). */
registerJobHandler("device.reevaluate", async (deps, job) => {
  await deps.db.tenant(job.org_id, async (tx) => {
    const d = await tx.selectFrom("devices").select([...EVAL_COLUMNS]).where("id", "=", String((job.payload as { device_id: string }).device_id)).where("status", "=", "active").executeTakeFirst();
    if (d) await evaluateDevice(tx, d, await getPolicies(tx), { meta: { ...SCHEDULER_META, requestId: job.id } });
  });
});

/** Every few minutes: devices whose grace period ran out are re-evaluated, even if they're offline. */
export function scheduleGraceChecks(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 5 * 60_000) return;
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; device_id: string }>`SELECT * FROM nexus_devices_grace_expired()`.execute(tx)).rows);
    for (const d of due) await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, "device.reevaluate", { device_id: d.device_id }, { dedupeKey: `device.reevaluate:${d.device_id}` }));
  });
}

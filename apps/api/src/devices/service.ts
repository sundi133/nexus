import type { RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { notifyUsers } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import type { Compliance, DevicePlatform } from "../platform/db-types.js";
import { aggregate, CHECK_KEYS, DEFAULT_POLICIES, evaluate, PostureFacts, type Policy } from "./posture.js";

export const ONLINE_WINDOW_MS = 3 * 60_000;
export const CHECKIN_INTERVAL_S = 60;
export const INVENTORY_INTERVAL_S = 900;

/** The org's policies: stored rows over defaults, in a stable order. */
export async function getPolicies(tx: Tx): Promise<Policy[]> {
  const rows = await tx.selectFrom("device_policies").selectAll().execute();
  return DEFAULT_POLICIES.map((d) => {
    const r = rows.find((x) => x.check_key === d.key);
    return r ? { key: d.key, enabled: r.enabled, params: { ...d.params, ...(r.params as object) } } : d;
  }).filter((p) => (CHECK_KEYS as readonly string[]).includes(p.key)) as Policy[];
}

type DeviceForEval = { id: string; org_id: string; hostname: string; platform: DevicePlatform; os_version: string; posture: unknown; compliance: Compliance; primary_user_id: string | null };

/**
 * Re-evaluates a device against the org's policies, stores per-check results,
 * and on a compliance change records it and tells the people who should act.
 */
export async function evaluateDevice(tx: Tx, device: DeviceForEval, policies: Policy[], who: { meta: RequestMeta }) {
  const facts = PostureFacts.safeParse(device.posture).data ?? null;
  const results = evaluate(device, facts, policies);
  const compliance = aggregate(results);

  await tx.deleteFrom("device_checks").where("device_id", "=", device.id).execute();
  if (results.length) {
    await tx
      .insertInto("device_checks")
      .values(results.map((r) => ({ org_id: device.org_id, device_id: device.id, check_key: r.key, status: r.status, detail: r.detail, updated_at: new Date() })))
      .execute();
  }
  if (compliance !== device.compliance) {
    await tx.updateTable("devices").set({ compliance, compliance_changed_at: new Date() }).where("id", "=", device.id).execute();
    const failing = results.filter((r) => r.status === "fail");
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
    .select(["id", "org_id", "hostname", "platform", "os_version", "posture", "compliance", "primary_user_id"])
    .where("status", "=", "active")
    .execute();
  let changed = 0;
  for (const d of devices) {
    const r = await evaluateDevice(tx, d, policies, who);
    if (r.compliance !== d.compliance) changed++;
  }
  return { devices: devices.length, changed };
}

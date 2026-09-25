import { sql } from "kysely";
import type { Tx } from "../platform/db.js";
import type { EvalContext, MdmSignal } from "./posture.js";

/** MDM signals for device evaluation (kept apart from mdm.ts so evaluation doesn't import the API). */

export const MDM_PROVIDER = { intune: "Microsoft Intune", jamf: "Jamf Pro" } as const;
const PROVIDER = MDM_PROVIDER;

const RANK = (m: MdmSignal) => (!m.managed ? 0 : m.compliant === false ? 1 : m.compliant === null ? 2 : 3);

/** What the org's MDMs say about this device: the worst verdict wins if several manage it. */
export async function mdmContext(tx: Tx, device: { id: string; serial?: string }): Promise<EvalContext> {
  const conns = await tx.selectFrom("mdm_connections").select(["id", "provider", "name"]).where("enabled", "=", true).execute();
  if (!conns.length) return { mdmConnected: false, mdm: null };
  let q = tx
    .selectFrom("mdm_devices")
    .select(["connection_id", "external_id", "managed", "compliant", "compliance_detail", "device_id"])
    .where("connection_id", "in", conns.map((c) => c.id));
  q = device.serial?.trim() ? q.where((eb) => eb.or([eb("device_id", "=", device.id), eb(sql`lower(serial)`, "=", device.serial!.trim().toLowerCase())])) : q.where("device_id", "=", device.id);
  const rows = await q.execute();
  // Link rows found by serial now, so the match doesn't wait for the next MDM sync.
  for (const r of rows.filter((r) => r.device_id !== device.id)) {
    await tx.updateTable("mdm_devices").set({ device_id: device.id }).where("connection_id", "=", r.connection_id).where("external_id", "=", r.external_id).execute();
  }
  if (!rows.length) return { mdmConnected: true, mdm: null };
  const signals = rows.map((r) => ({ source: PROVIDER[conns.find((c) => c.id === r.connection_id)!.provider], managed: r.managed, compliant: r.compliant, detail: r.compliance_detail }));
  return { mdmConnected: true, mdm: signals.sort((a, b) => RANK(a) - RANK(b))[0]! };
}


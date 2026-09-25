import { sql } from "kysely";
import type { Tx } from "../platform/db.js";
import type { EvalContext, MdmSignal } from "./posture.js";

/** MDM signals for device evaluation (kept apart from mdm.ts so evaluation doesn't import the API). */

export const MDM_PROVIDER = { intune: "Microsoft Intune", jamf: "Jamf Pro" } as const;
const PROVIDER = MDM_PROVIDER;

const RANK = (m: MdmSignal) => (!m.managed ? 0 : m.compliant === false ? 1 : m.compliant === null ? 2 : 3);

/**
 * The MDM records for a device: linked by the last MDM sync, or found by serial
 * number (a device enrolled since). Read-only, so evaluating a device never
 * contends with an MDM sync writing the same rows.
 */
export async function mdmRowsForDevice(tx: Tx, device: { id: string; serial?: string | null }) {
  let q = tx
    .selectFrom("mdm_devices")
    .innerJoin("mdm_connections", "mdm_connections.id", "mdm_devices.connection_id")
    .select([
      "mdm_connections.id as connection_id",
      "mdm_connections.provider",
      "mdm_connections.name as connection",
      "mdm_connections.config",
      "mdm_connections.secret",
      "mdm_devices.external_id",
      "mdm_devices.management_id",
      "mdm_devices.managed",
      "mdm_devices.compliant",
      "mdm_devices.compliance_detail",
      "mdm_devices.encrypted",
      "mdm_devices.last_contact_at",
    ])
    .where("mdm_connections.enabled", "=", true);
  const serial = device.serial?.trim().toLowerCase();
  q = serial ? q.where((eb) => eb.or([eb("mdm_devices.device_id", "=", device.id), eb(sql`lower(mdm_devices.serial)`, "=", serial)])) : q.where("mdm_devices.device_id", "=", device.id);
  return q.execute();
}

/** What the org's MDMs say about this device: the worst verdict wins if several manage it. */
export async function mdmContext(tx: Tx, device: { id: string; serial?: string | null }): Promise<EvalContext> {
  const connected = await tx.selectFrom("mdm_connections").select("id").where("enabled", "=", true).executeTakeFirst();
  if (!connected) return { mdmConnected: false, mdm: null };
  const rows = await mdmRowsForDevice(tx, device);
  if (!rows.length) return { mdmConnected: true, mdm: null };
  const signals = rows.map((r) => ({ source: PROVIDER[r.provider], managed: r.managed, compliant: r.compliant, detail: r.compliance_detail }));
  return { mdmConnected: true, mdm: signals.sort((a, b) => RANK(a) - RANK(b))[0]! };
}

import type { Tx } from "../platform/db.js";
import { enqueue } from "../platform/jobs.js";

/** People changed: re-evaluate the organization's dynamic groups soon (one queued job per org at a time). */
export async function scheduleDynamicEvaluation(tx: Tx, orgId: string) {
  const any = await tx.selectFrom("groups").select("id").where("rule", "is not", null).executeTakeFirst();
  if (any) await enqueue(tx, orgId, "groups.dynamic", {}, { dedupeKey: "groups.dynamic" });
}

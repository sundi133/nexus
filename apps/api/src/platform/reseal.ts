import pg from "pg";
import type { Sealer } from "./seal.js";

/**
 * Re-encrypts every sealed secret with the current key (ADR-024), so an old
 * key can be removed from NEXUS_SEAL_KEYS. Runs as the owner role, like
 * migrations: it has to reach every tenant.
 */

type Target = { table: string; pk: string; column: string; aad: (row: Record<string, string>) => string };

export const SEALED: Target[] = [
  { table: "auth_factors", pk: "id", column: "secret_sealed", aad: (r) => r.id! },
  { table: "signing_keys", pk: "id", column: "private_key_sealed", aad: (r) => r.kid! },
  { table: "directory_connections", pk: "id", column: "secret", aad: (r) => `directory_connection:${r.id}` },
  { table: "app_provisioning", pk: "app_id", column: "token", aad: (r) => `app_provisioning:${r.app_id}` },
  { table: "event_destinations", pk: "id", column: "secret", aad: (r) => `event_destination:${r.id}` },
  { table: "org_alert_channels", pk: "org_id", column: "slack_webhook", aad: (r) => `org_alert_channels:${r.org_id}` },
];

export type ResealReport = { table: string; checked: number; resealed: number; failed: string[] }[];

export async function reseal(ownerUrl: string, sealer: Sealer, opts: { dryRun?: boolean; orgId?: string } = {}): Promise<ResealReport> {
  const client = new pg.Client({ connectionString: ownerUrl });
  await client.connect();
  const report: ResealReport = [];
  try {
    for (const t of SEALED) {
      const extra = t.table === "signing_keys" ? ", kid" : "";
      const rows = (
        await client.query(`SELECT ${t.pk}${extra}, ${t.column} AS sealed FROM ${t.table} WHERE ${t.column} IS NOT NULL${opts.orgId ? " AND org_id = $1" : ""}`, opts.orgId ? [opts.orgId] : [])
      ).rows as (Record<string, string> & { sealed: Buffer })[];
      const entry = { table: t.table, checked: rows.length, resealed: 0, failed: [] as string[] };
      for (const row of rows) {
        const aad = t.aad(row);
        if (!sealer.needsReseal(row.sealed, aad)) continue;
        let plain: Buffer;
        try {
          plain = sealer.open(row.sealed, aad);
        } catch {
          entry.failed.push(String(row[t.pk])); // sealed with a key that's no longer configured
          continue;
        }
        if (!opts.dryRun) {
          // Only if unchanged since we read it, so a concurrent write isn't overwritten.
          const r = await client.query(`UPDATE ${t.table} SET ${t.column} = $1 WHERE ${t.pk} = $2 AND ${t.column} = $3`, [sealer.seal(plain, aad), row[t.pk], row.sealed]);
          if (r.rowCount) entry.resealed++;
        } else entry.resealed++;
      }
      report.push(entry);
    }
  } finally {
    await client.end();
  }
  return report;
}

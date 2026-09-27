import { sql } from "kysely";
import type { Tx } from "../platform/db.js";

/**
 * What data exports leave out. Secrets are stored as bytea (sealed values, hashes, key material),
 * so every bytea column is dropped; these are the few text columns that also hold one.
 */
const SECRET_TEXT = new Set([
  "users.password_hash",
  "agent_credentials.secret_hash",
  "auth_challenges.challenge",
  "federation_requests.code_verifier",
  "federation_requests.nonce",
  "oidc_codes.code_challenge",
  "oidc_codes.nonce",
  "push_registrations.token",
  "device_trust_challenges.nonce",
  "org_domains.token",
]);

/** Short-lived sign-in artifacts and internal bookkeeping: not the customer's data, never exported. */
export const SKIP_TABLES = new Set([
  "jobs",
  "agent_nonces",
  "oidc_codes",
  "auth_challenges",
  "mfa_challenges",
  "password_resets",
  "federation_requests",
  "device_trust_challenges",
  "rate_limits",
  "schedule_runs",
  "schema_migrations",
  "deleted_organizations",
]);

export type Columns = { keep: string[]; dropped: string[] };

/** A table's columns, split into what an export includes and what it leaves out as secret. */
export async function exportColumns(tx: Tx, table: string): Promise<Columns> {
  const rows = (
    await sql<{ name: string; type: string }>`
      SELECT a.attname AS name, t.typname AS type FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid
      WHERE a.attrelid = ${table}::regclass AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`.execute(tx)
  ).rows;
  const out: Columns = { keep: [], dropped: [] };
  for (const r of rows) (r.type === "bytea" || SECRET_TEXT.has(`${table}.${r.name}`) ? out.dropped : out.keep).push(r.name);
  return out;
}

/** Selects the kept columns of rows matching `where` (a SQL fragment), in a stable order. */
export function selectKept(table: string, cols: Columns, where: ReturnType<typeof sql>) {
  return sql<Record<string, unknown>>`SELECT ${sql.join(cols.keep.map((c) => sql.id(c)))} FROM ${sql.id(table)} WHERE ${where}`;
}

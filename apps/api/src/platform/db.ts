import { Kysely, PostgresDialect, sql, type Transaction } from "kysely";
import pg from "pg";
import type { Database } from "./db-types.js";

export type Tx = Transaction<Database>;

// Return bigint/numeric as numbers where safe; timestamps stay Date.
pg.types.setTypeParser(20, (v) => Number(v));

/**
 * Tenant-scoped database access.
 *
 * `tenant()` opens a transaction and sets app.org_id so Postgres row-level
 * security filters every statement. The runtime role cannot bypass RLS;
 * cross-tenant lookups exist only as narrow SECURITY DEFINER functions.
 */
export class Db {
  readonly pool: pg.Pool;
  readonly kysely: Kysely<Database>;

  constructor(url: string) {
    this.pool = new pg.Pool({ connectionString: url, max: 20 });
    this.kysely = new Kysely<Database>({ dialect: new PostgresDialect({ pool: this.pool }) });
  }

  tenant<T>(orgId: string, fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.kysely.transaction().execute(async (tx) => {
      await sql`SELECT set_config('app.org_id', ${orgId}, true)`.execute(tx);
      return fn(tx);
    });
  }

  /** No tenant set: RLS hides all tenant rows; only the SECURITY DEFINER functions return data. */
  unscoped<T>(fn: (tx: Tx) => Promise<T>): Promise<T> {
    return this.kysely.transaction().execute(fn);
  }

  async close() {
    await this.kysely.destroy();
  }
}

export function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "23505";
}

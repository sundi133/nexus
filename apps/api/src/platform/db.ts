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
    this.pool = new pg.Pool({
      connectionString: url,
      max: Number(process.env.NEXUS_DB_POOL_SIZE) || 20,
      // During a database failover, fail fast instead of hanging: new connections time out, and
      // TCP keepalive finds connections to the old primary that died without a goodbye.
      connectionTimeoutMillis: Number(process.env.NEXUS_DB_CONNECT_TIMEOUT_MS) || 5000,
      keepAlive: true,
      keepAliveInitialDelayMillis: 10_000,
    });
    // A connection the server drops while idle (a restart, a failover) is reported here; without a
    // listener Node would crash the whole process. The pool discards it and reconnects on next use.
    this.pool.on("error", (err) => console.error(JSON.stringify({ level: "warn", msg: "database connection lost; reconnecting", error: err.message })));
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

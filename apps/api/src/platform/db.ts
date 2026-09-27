import { Kysely, PostgresDialect, sql, type Transaction } from "kysely";
import pg from "pg";
import type { Database } from "./db-types.js";

export type Tx = Transaction<Database>;

// Return bigint/numeric as numbers where safe; timestamps stay Date.
pg.types.setTypeParser(20, (v) => Number(v));

/**
 * Connections that survive a database going away. A query that timed out is on a dead
 * connection (its answer may never come): destroy it, so the pool drops it instead of queueing
 * the next query behind the lost one.
 */
class GuardedClient extends pg.Client {
  constructor(config?: string | pg.ClientConfig) {
    super(config);
    // The pool listens for errors only while a connection is idle. One that breaks while in use
    // (the server restarting or failing over) would emit an unhandled 'error' and crash the
    // process; its queries have already been rejected to their callers, so this only needs to
    // be heard. The pool drops the broken connection when it's released.
    this.on("error", () => {});
  }

  override query(...args: unknown[]): never {
    const r = (super.query as (...a: unknown[]) => unknown)(...args);
    if (r && typeof (r as Promise<unknown>).catch === "function") {
      (r as Promise<unknown>).catch((e: Error) => {
        if (/timeout/i.test(e?.message ?? "")) (this as unknown as { connection: { stream: { destroy(): void } } }).connection.stream.destroy();
      });
    }
    return r as never;
  }
}

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

  constructor(url: string, opts: { queryTimeoutMs?: number; poolSize?: number } = {}) {
    this.pool = new pg.Pool({
      connectionString: url,
      max: opts.poolSize ?? (Number(process.env.NEXUS_DB_POOL_SIZE) || 20),
      // During a database failover, fail fast instead of hanging: new connections time out, and
      // TCP keepalive finds connections to the old primary that died without a goodbye.
      connectionTimeoutMillis: Number(process.env.NEXUS_DB_CONNECT_TIMEOUT_MS) || 5000,
      keepAlive: true,
      keepAliveInitialDelayMillis: 10_000,
      // A server that vanished (a failover, a deleted pod) never answers: without a limit, the
      // queries in flight hold every connection forever and nothing recovers.
      query_timeout: opts.queryTimeoutMs ?? (Number(process.env.NEXUS_DB_QUERY_TIMEOUT_MS) || 30_000),
      Client: GuardedClient,
    });
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

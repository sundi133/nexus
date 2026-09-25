import { sql } from "kysely";
import type { Db } from "../platform/db.js";

/**
 * Fixed-window rate limits for sensitive endpoints (sign-in, MFA, API keys,
 * the MCP gateway...). With a shared backend (Postgres, set at startup) every
 * API replica counts together, so running several doesn't multiply the limits.
 * Without one (tests), or if the database can't answer, the process counts on
 * its own, so a limit always applies.
 */

let shared: Db | null = null;
let lastSweep = 0;

/** Called at startup: counts are kept in Postgres from then on. */
export function useSharedRateLimits(db: Db | null) {
  shared = db;
}

export class RateLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    /** Stable across replicas: namespaces the keys. */
    private readonly name: string,
  ) {}

  /** Resolves true if the call is allowed. */
  async take(key: string): Promise<boolean> {
    if (shared) {
      try {
        return (await this.takeShared(shared, key)) <= this.max;
      } catch (err) {
        console.error(`[ratelimit] shared counter unavailable, counting locally: ${(err as Error).message}`);
      }
    }
    return this.takeLocal(key);
  }

  private async takeShared(db: Db, key: string): Promise<number> {
    const k = `${this.name}:${key}`;
    const secs = Math.ceil(this.windowMs / 1000);
    const n = await db.unscoped(async (tx) => {
      const r = await sql<{ count: number }>`
        INSERT INTO rate_limits (key, reset_at, count) VALUES (${k}, now() + make_interval(secs => ${secs}), 1)
        ON CONFLICT (key) DO UPDATE SET
          count = CASE WHEN rate_limits.reset_at <= now() THEN 1 ELSE rate_limits.count + 1 END,
          reset_at = CASE WHEN rate_limits.reset_at <= now() THEN now() + make_interval(secs => ${secs}) ELSE rate_limits.reset_at END
        RETURNING count`.execute(tx);
      if (Date.now() - lastSweep > 10 * 60_000) {
        lastSweep = Date.now();
        await sql`DELETE FROM rate_limits WHERE reset_at < now() - interval '1 hour'`.execute(tx);
      }
      return r.rows[0]!.count;
    });
    return n;
  }

  private takeLocal(key: string): boolean {
    const now = Date.now();
    const cur = this.hits.get(key);
    if (!cur || cur.resetAt <= now) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      if (this.hits.size > 50_000) this.sweep(now);
      return true;
    }
    cur.count++;
    return cur.count <= this.max;
  }

  private sweep(now: number) {
    for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
  }
}

/**
 * Fixed-window in-memory limiter for auth endpoints. Per-process only; moves
 * to Redis when the API runs as multiple replicas (ARCHITECTURE §4).
 */
export class RateLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  /** Returns true if the call is allowed. */
  take(key: string): boolean {
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

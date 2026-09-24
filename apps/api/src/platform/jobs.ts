import { sql } from "kysely";
import type { Deps } from "../context.js";
import type { Tx } from "./db.js";
import { newId } from "./ids.js";

/**
 * Durable background jobs (ARCHITECTURE §9). Enqueue inside the transaction
 * that makes the work necessary, so a job exists iff its cause committed.
 * Handlers must be idempotent: a job can run more than once (lease expiry).
 */

export type Job = { id: string; org_id: string; kind: string; payload: Record<string, unknown>; attempts: number; max_attempts: number };
export type JobHandler = (deps: Deps, job: Job) => Promise<void>;

const handlers = new Map<string, JobHandler>();

export function registerJobHandler(kind: string, fn: JobHandler) {
  handlers.set(kind, fn);
}

/** A failure the handler knows retrying won't fix (bad configuration, 4xx). */
export class PermanentJobError extends Error {}

export async function enqueue(
  tx: Tx,
  orgId: string,
  kind: string,
  payload: Record<string, unknown> = {},
  opts: { runAt?: Date; dedupeKey?: string; maxAttempts?: number } = {},
) {
  const id = newId();
  const r = await tx
    .insertInto("jobs")
    .values({
      id,
      org_id: orgId,
      kind,
      payload: JSON.stringify(payload),
      run_at: opts.runAt ?? new Date(),
      dedupe_key: opts.dedupeKey ?? null,
      max_attempts: opts.maxAttempts ?? 8,
    })
    .onConflict((oc) => oc.columns(["org_id", "dedupe_key"]).where("status", "=", "queued").where("dedupe_key", "is not", null).doNothing())
    .returning("id")
    .executeTakeFirst();
  return r?.id ?? null; // null: an identical job is already queued (a running one doesn't count: it may have read stale state)
}

/** 30 s, 1 min, 2 min … capped at 1 h. */
export const backoff = (attempts: number) => Math.min(3600, 30 * 2 ** Math.max(0, attempts - 1)) * 1000;

const LEASE_SECONDS = 300;

export class JobRunner {
  private timer: NodeJS.Timeout | null = null;
  private running = false;
  private ticks: (() => Promise<void>)[] = [];

  constructor(private deps: Deps) {}

  /** Periodic work (e.g. enqueue due syncs), run by the polling loop. */
  onTick(fn: () => Promise<void>) {
    this.ticks.push(fn);
  }

  /** Claims and runs ready jobs until none are left. `orgId` limits it to one tenant (tests). */
  async runOnce(opts: { orgId?: string; limit?: number } = {}): Promise<number> {
    let total = 0;
    for (;;) {
      const batch = await this.deps.db.unscoped(async (tx) => {
        const r = await sql<Job>`SELECT * FROM nexus_claim_jobs(${opts.limit ?? 10}, ${LEASE_SECONDS}, ${opts.orgId ?? null})`.execute(tx);
        return r.rows;
      });
      if (batch.length === 0) return total;
      total += batch.length;
      await Promise.all(batch.map((j) => this.run(j)));
    }
  }

  private async run(job: Job) {
    const handler = handlers.get(job.kind);
    let error: string | null = null;
    let retryAt: Date | null = null;
    try {
      if (!handler) throw new PermanentJobError(`No handler for job kind ${job.kind}`);
      await handler(this.deps, job);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      if (!(err instanceof PermanentJobError) && job.attempts < job.max_attempts) retryAt = new Date(Date.now() + backoff(job.attempts));
      if (!retryAt) console.error(`[jobs] ${job.kind} ${job.id} gave up: ${error}`);
    }
    await this.deps.db.unscoped((tx) => sql`SELECT nexus_finish_job(${job.id}::uuid, ${error}, ${retryAt})`.execute(tx));
  }

  start(intervalMs = 2000) {
    const loop = async () => {
      if (this.running) return;
      this.running = true;
      try {
        for (const t of this.ticks) await t().catch((e) => console.error("[jobs] tick failed", e));
        await this.runOnce();
      } catch (err) {
        console.error("[jobs] loop failed", err);
      } finally {
        this.running = false;
      }
    };
    this.timer = setInterval(loop, intervalMs);
    void loop();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
  }
}

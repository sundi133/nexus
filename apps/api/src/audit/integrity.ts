import { createHash } from "node:crypto";
import { sql } from "kysely";
import type { Deps, RequestMeta } from "../context.js";
import { canonical } from "../platform/canonical.js";
import type { Tx } from "../platform/db.js";
import { enqueue, type JobRunner, registerJobHandler } from "../platform/jobs.js";
import { notifyRoles } from "../notify/send.js";
import { audit } from "./record.js";

/**
 * Tamper evidence for the audit log (SPEC AUD-05). Each organization's events
 * are hashed into a chain in commit order (txid, id) — the same gapless order
 * event streaming uses, so an event from a long transaction is never skipped.
 * The chain is sealed into blocks at least hourly; each seal is itself an
 * audit event, so the digest also lands in the organization's SIEM and
 * archive, outside Nexus. Verification recomputes every retained block.
 *
 * Deleting an organization must set `nexus.audit_prune = on` in its
 * transaction: the database refuses any other change to audit rows.
 */

export const GENESIS = "0".repeat(64);
const MAX_BLOCK = 50_000;

type EventRow = {
  id: string;
  org_id: string;
  ts: Date;
  type: string;
  outcome: string;
  actor_type: string;
  actor_id: string | null;
  actor_display: string;
  target_type: string;
  target_id: string | null;
  target_display: string;
  session_id: string | null;
  ip: string;
  user_agent: string;
  details: unknown;
  txid_text: string;
};

/** The hash of one event: every column, canonically encoded. */
export function eventHash(e: EventRow): string {
  return createHash("sha256")
    .update(
      canonical({
        id: e.id,
        org: e.org_id,
        ts: e.ts.toISOString(),
        type: e.type,
        outcome: e.outcome,
        actor: [e.actor_type, e.actor_id, e.actor_display],
        target: [e.target_type, e.target_id, e.target_display],
        session: e.session_id,
        ip: e.ip,
        ua: e.user_agent,
        details: e.details ?? {},
        txid: e.txid_text,
      }),
    )
    .digest("hex");
}

export const link = (prev: string, eventDigest: string) => createHash("sha256").update(prev).update(eventDigest).digest("hex");

const ZERO = { txid: "0", id: "00000000-0000-0000-0000-000000000000" };

async function lastBlock(tx: Tx) {
  return tx.selectFrom("audit_blocks").selectAll().orderBy("seq", "desc").limit(1).executeTakeFirst();
}

async function eventsBetween(tx: Tx, from: { txid: string; id: string }, to: { txid: string; id: string } | null, limit = MAX_BLOCK) {
  const rows = await sql<EventRow>`
    SELECT e.*, e.txid::text AS txid_text FROM audit_events e
    WHERE (e.txid, e.id) > (${from.txid}::xid8, ${from.id}::uuid)
      AND ${to ? sql`(e.txid, e.id) <= (${to.txid}::xid8, ${to.id}::uuid)` : sql`e.txid < pg_snapshot_xmin(pg_current_snapshot())`}
    ORDER BY e.txid, e.id
    LIMIT ${limit}`.execute(tx);
  return rows.rows;
}

/** Seals every committed, unsealed event of the organization into a new block. */
export async function seal(deps: Deps, orgId: string, meta: RequestMeta) {
  return deps.db.tenant(orgId, async (tx) => {
    // One sealer per organization at a time.
    await sql`SELECT pg_advisory_xact_lock(hashtext('audit-seal:' || ${orgId}))`.execute(tx);
    const prev = await lastBlock(tx);
    const from = prev ? { txid: prev.to_txid, id: prev.to_id } : ZERO;
    const events = await eventsBetween(tx, from, null);
    if (!events.length) return null;
    let digest = prev?.digest ?? GENESIS;
    for (const e of events) digest = link(digest, eventHash(e));
    const last = events[events.length - 1]!;
    const seq = Number(prev?.seq ?? 0) + 1;
    await tx
      .insertInto("audit_blocks")
      .values({
        org_id: orgId,
        seq,
        from_txid: from.txid,
        from_id: from.id,
        to_txid: last.txid_text,
        to_id: last.id,
        count: events.length,
        first_ts: new Date(Math.min(...events.map((e) => e.ts.getTime()))),
        last_ts: new Date(Math.max(...events.map((e) => e.ts.getTime()))),
        prev_digest: prev?.digest ?? GENESIS,
        digest,
      })
      .execute();
    // The seal is an event too: it reaches the org's SIEM/archive (the anchor) and is chained into the next block.
    await audit(tx, orgId, { meta }, { type: "audit.sealed", actor: { type: "system", id: null, display: "Audit log" }, details: { block: seq, events: events.length, digest, prev_digest: prev?.digest ?? GENESIS } });
    return { seq, count: events.length, digest };
  });
}

export type Problem = { block: number; kind: "modified_or_missing" | "count" | "chain_broken" | "unsealed_gap"; detail: string };
export type Verification = {
  ok: boolean;
  blocks_checked: number;
  events_checked: number;
  pruned_blocks: number;
  head: { block: number; digest: string; sealed_at: string } | null;
  problem: Problem | null;
};

/** Recomputes every retained block and checks that the blocks link up. */
export async function verify(tx: Tx, opts: { sinceBlock?: number } = {}): Promise<Verification> {
  const blocks = await tx.selectFrom("audit_blocks").selectAll().where("seq", ">=", String(opts.sinceBlock ?? 1)).orderBy("seq").execute();
  const out: Verification = { ok: true, blocks_checked: 0, events_checked: 0, pruned_blocks: 0, head: null, problem: null };
  let prev: (typeof blocks)[number] | undefined;
  if (opts.sinceBlock && opts.sinceBlock > 1) prev = await tx.selectFrom("audit_blocks").selectAll().where("seq", "=", String(opts.sinceBlock - 1)).executeTakeFirst();
  for (const b of blocks) {
    const fail = (p: Problem) => ({ ...out, ok: false, problem: p });
    if (prev && (b.prev_digest !== prev.digest || b.from_txid !== prev.to_txid || b.from_id !== prev.to_id)) return fail({ block: Number(b.seq), kind: "chain_broken", detail: `Block ${b.seq} doesn't continue block ${prev.seq}` });
    if (!prev && Number(b.seq) === 1 && b.prev_digest !== GENESIS) return fail({ block: 1, kind: "chain_broken", detail: "The first block doesn't start the chain" });
    prev = b;
    if (b.pruned_at) {
      out.pruned_blocks++;
      continue;
    }
    const events = await eventsBetween(tx, { txid: b.from_txid, id: b.from_id }, { txid: b.to_txid, id: b.to_id }, b.count + 1);
    if (events.length !== b.count) return fail({ block: Number(b.seq), kind: "count", detail: `Block ${b.seq} sealed ${b.count} events; ${events.length} are there now` });
    let d = b.prev_digest;
    for (const e of events) d = link(d, eventHash(e));
    if (d !== b.digest) return fail({ block: Number(b.seq), kind: "modified_or_missing", detail: `An event in block ${b.seq} (${b.first_ts.toISOString()} to ${b.last_ts.toISOString()}) was changed, removed or added` });
    out.blocks_checked++;
    out.events_checked += events.length;
  }
  if (prev) out.head = { block: Number(prev.seq), digest: prev.digest, sealed_at: prev.sealed_at.toISOString() };
  return out;
}

// ---- Jobs -------------------------------------------------------------------------------

const SYSTEM: RequestMeta = { ip: "", userAgent: "nexus-audit", requestId: "" };

registerJobHandler("audit.seal", async (deps, job) => {
  await seal(deps, job.org_id, { ...SYSTEM, requestId: job.id });
});

registerJobHandler("audit.verify", async (deps, job) => {
  await deps.db.tenant(job.org_id, async (tx) => {
    const v = await verify(tx);
    if (v.ok) return;
    await audit(tx, job.org_id, { meta: { ...SYSTEM, requestId: job.id } }, { type: "audit.integrity_failed", outcome: "failure", actor: { type: "system", id: null, display: "Audit log" }, details: { ...v.problem } });
    await notifyRoles(tx, job.org_id, ["owner", "admin", "security_analyst"], {
      category: "security.alert",
      severity: "critical",
      title: "The audit log failed its integrity check",
      body: v.problem?.detail,
      link: "/audit?integrity=1",
    });
  });
});

/** Seals hourly, verifies and applies retention daily. */
export function scheduleAuditIntegrity(jobs: JobRunner, deps: Deps) {
  let lastSeal = 0;
  let lastDaily = 0;
  jobs.onTick(async () => {
    const now = Date.now();
    if (now - lastSeal >= 60 * 60_000) {
      lastSeal = now;
      const orgs = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_audit_unsealed()`.execute(tx)).rows);
      for (const o of orgs) await deps.db.tenant(o.org_id, (tx) => enqueue(tx, o.org_id, "audit.seal", {}, { dedupeKey: "audit.seal" }));
    }
    if (now - lastDaily >= 24 * 60 * 60_000) {
      lastDaily = now;
      await deps.db.unscoped((tx) => sql`SELECT * FROM nexus_prune_audit(500)`.execute(tx));
      const orgs = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_audit_chained_orgs()`.execute(tx)).rows);
      for (const o of orgs) await deps.db.tenant(o.org_id, (tx) => enqueue(tx, o.org_id, "audit.verify", {}, { dedupeKey: "audit.verify" }));
    }
  });
}

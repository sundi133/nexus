import { sql } from "kysely";
import type { Deps } from "../context.js";
import { notifyRoles } from "../notify/send.js";
import { newId } from "../platform/ids.js";
import { backoff, enqueue, registerJobHandler, type JobRunner } from "../platform/jobs.js";
import { assertSafeUrl } from "../platform/outbound.js";
import { formatEvent, matchesFilter, type AuditRow } from "./formats.js";
import { ARCHIVE_FLUSH_MS, BATCH, isArchive, send } from "./senders.js";

/**
 * Streams the audit log to webhooks and SIEMs (INT-03, AUD-04). Each
 * destination has a cursor (txid, id) into audit_events; delivery is ordered,
 * at-least-once, resumes after outages, and never skips an event (ADR-021).
 */

export const secretAad = (id: string) => `event_destination:${id}`;
const ALERT_AFTER = 5;
const DISABLE_AFTER = 100;
const MAX_ROUNDS = 20; // per job run; the next tick continues a big backlog

type Row = AuditRow & { txid_text: string };

export async function deliver(deps: Deps, orgId: string, destinationId: string) {
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const work = await deps.db.tenant(orgId, async (tx) => {
      const d = await tx.selectFrom("event_destinations").selectAll().where("id", "=", destinationId).executeTakeFirst();
      if (!d || !d.enabled) return null;
      const rows = (
        await sql<Row>`
          SELECT e.*, e.txid::text AS txid_text FROM audit_events e
          WHERE (e.txid, e.id) > (${d.cursor_txid}::xid8, ${d.cursor_id}::uuid)
            AND e.txid < pg_snapshot_xmin(pg_current_snapshot())
          ORDER BY e.txid, e.id
          LIMIT ${BATCH[d.kind] * 4}`.execute(tx)
      ).rows;
      return { d, rows };
    });
    if (!work || work.rows.length === 0) return;
    const { d, rows } = work;

    // Take matching events up to the batch size; the cursor may skip past non-matching ones.
    const batch: Row[] = [];
    let scannedTo = rows.length - 1;
    for (let i = 0; i < rows.length; i++) {
      if (!matchesFilter(d.event_filter, rows[i]!.type)) continue;
      if (batch.length === BATCH[d.kind]) {
        scannedTo = i - 1;
        break;
      }
      batch.push(rows[i]!);
    }

    // Archives wait for a full object's worth of events, or until the oldest has waited long enough.
    if (batch.length && isArchive(d.kind) && batch.length < BATCH[d.kind] && rows.length < BATCH[d.kind] * 4) {
      const due = batch[0]!.ts.getTime() + ARCHIVE_FLUSH_MS;
      if (due > Date.now()) {
        await deps.db.tenant(orgId, (tx) => tx.updateTable("event_destinations").set({ next_attempt_at: new Date(due) }).where("id", "=", d.id).execute());
        return;
      }
    }

    let delivered = 0;
    let result = { delivered: 0, status: 0, error: "" };
    const started = Date.now();
    if (batch.length) {
      try {
        await assertSafeUrl(d.url, { allowPrivate: deps.cfg.allowPrivateOutbound }); // DNS can change after setup
        const secret = deps.sealer.open(d.secret, secretAad(d.id)).toString();
        result = await send(d.kind, d.url, secret, d.config as Record<string, string>, batch.map((e) => ({ id: e.id, type: e.type, time: e.ts, body: formatEvent(d.format, e) })), { entraLoginBase: deps.cfg.entraLoginBase });
      } catch (err) {
        result = { delivered: 0, status: 0, error: (err as Error).message };
      }
      delivered = result.delivered;
    }
    // Where the cursor may move: past everything scanned if all matches went out, else just past the last delivered one.
    const cursorRow = !batch.length || delivered === batch.length ? rows[scannedTo]! : delivered > 0 ? batch[delivered - 1]! : null;

    await deps.db.tenant(orgId, async (tx) => {
      if (cursorRow) {
        await tx.updateTable("event_destinations").set({ cursor_txid: cursorRow.txid_text, cursor_id: cursorRow.id }).where("id", "=", d.id).execute();
      }
      if (!batch.length) return;
      await tx
        .insertInto("event_deliveries")
        .values({ id: newId(), org_id: orgId, destination_id: d.id, ok: !result.error, http_status: result.status, events: delivered, duration_ms: Date.now() - started, error: result.error })
        .execute();
      if (!result.error) {
        await tx.updateTable("event_destinations").set({ consecutive_failures: 0, last_error: "", last_delivered_at: new Date(), next_attempt_at: sql<Date>`now()` }).where("id", "=", d.id).execute();
        return;
      }
      const failures = d.consecutive_failures + 1;
      const disable = failures >= DISABLE_AFTER;
      await tx
        .updateTable("event_destinations")
        .set({
          consecutive_failures: failures,
          last_error: result.error,
          next_attempt_at: new Date(Date.now() + backoff(failures)),
          ...(disable ? { enabled: false, disabled_reason: `Turned off after ${failures} failed deliveries in a row: ${result.error}` } : {}),
          ...(delivered ? { last_delivered_at: new Date() } : {}),
        })
        .where("id", "=", d.id)
        .execute();
      if (failures === ALERT_AFTER || disable) {
        await notifyRoles(tx, orgId, ["owner", "admin"], {
          category: "integrations.delivery",
          severity: disable ? "critical" : "warning",
          title: disable ? `${d.name} was turned off` : `Can't deliver events to ${d.name}`,
          body: disable
            ? `After ${failures} failed attempts. Events are kept: fix the endpoint and turn it back on to resume where it stopped.`
            : `${result.error}. Nexus keeps retrying with backoff; nothing is lost.`,
          entity: { type: "event_destination", id: d.id },
          link: "/integrations",
        });
      }
      // Keep the delivery log short.
      await sql`DELETE FROM event_deliveries WHERE destination_id = ${d.id} AND id NOT IN (SELECT id FROM event_deliveries WHERE destination_id = ${d.id} ORDER BY at DESC LIMIT 200)`.execute(tx);
    });
    if (result.error) return; // back off; the tick retries after next_attempt_at
  }
}

registerJobHandler("events.deliver", async (deps, job) => {
  await deliver(deps, job.org_id, String((job.payload as { destination_id: string }).destination_id));
});

export const deliverKey = (id: string) => `events.deliver:${id}`;

/** Every few seconds: destinations with waiting events get a delivery job (one at a time each, in order). */
export function scheduleEventDelivery(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 4000) return;
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; destination_id: string }>`SELECT * FROM nexus_destinations_with_backlog()`.execute(tx)).rows);
    for (const d of due) {
      await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, "events.deliver", { destination_id: d.destination_id }, { dedupeKey: deliverKey(d.destination_id), maxAttempts: 1 }));
    }
  });
}

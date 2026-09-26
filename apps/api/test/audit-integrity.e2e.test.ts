import { sql } from "kysely";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Tamper-evident audit log and retention (AUD-03, AUD-05). */

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;

async function org(name: string) {
  const email = uniqueEmail(name.toLowerCase().replace(/\W+/g, ""));
  const s = await h.call("POST", "/v1/signup", { body: { organization_name: name, email, password: PASSWORD, given_name: "Root" } });
  if (s.status !== 201) throw new Error(`signup: ${s.status} ${JSON.stringify(s.body)}`);
  const token = s.body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  const orgId = (await h.call("GET", "/v1/me", { token })).body.organization.id as string;
  for (const n of ["a", "b", "c"]) await h.call("POST", "/v1/groups", { token, body: { name: `${name}-${n}` } });
  return { token, orgId };
}
const integrity = (token: string) => h.call("GET", "/v1/audit/integrity", { token }).then((r) => r.body);
const seal = (token: string) => h.call("POST", "/v1/audit/seal", { token, body: {} }).then((r) => r.body.sealed);
/** A privileged attacker with database access: triggers off for their session, then an edit. */
async function tamper(query: string, params: unknown[]) {
  await owner.query("SET session_replication_role = replica"); // this session only: triggers off
  try {
    await owner.query(query, params);
  } finally {
    await owner.query("SET session_replication_role = origin");
  }
}

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

describe("the chain", () => {
  it("seals committed events into linked blocks, and publishes each seal", async () => {
    const { token } = await org("Chain Co");
    expect((await integrity(token)).head).toBeNull();
    const b1 = await seal(token);
    expect(b1).toMatchObject({ block: 1 });
    expect(b1.events).toBeGreaterThanOrEqual(5);
    await h.call("POST", "/v1/groups", { token, body: { name: "later" } });
    const b2 = await seal(token);
    expect(b2.block).toBe(2);
    expect(b2.events).toBe(2); // the audit.sealed event from block 1, and the new group
    expect(await seal(token)).toMatchObject({ block: 3, events: 1 }); // just block 2's seal event
    const v = await integrity(token);
    expect(v).toMatchObject({ ok: true, blocks_checked: 3, head: { block: 3 }, problem: null, retention_days: 365 });
    const blocks = (await h.call("GET", "/v1/audit/blocks", { token })).body.data;
    expect(blocks[0].prev_digest).toBe(blocks[1].digest);
    const sealed = (await h.call("GET", "/v1/audit/events?type=audit.sealed", { token })).body.data;
    expect(sealed.map((e: any) => e.details.digest)).toContain(b1.digest);
  });

  it("can't be edited by the application, or by accident", async () => {
    const { orgId } = await org("Locked Co");
    const upd = h.deps.db.tenant(orgId, (tx) => sql`UPDATE audit_events SET type = 'x'`.execute(tx));
    await expect(upd).rejects.toThrow(/permission denied/);
    const del = h.deps.db.tenant(orgId, (tx) => sql`DELETE FROM audit_events`.execute(tx));
    await expect(del).rejects.toThrow(/permission denied/);
    // Even the table owner is stopped by the trigger.
    await expect(owner.query("UPDATE audit_events SET type = 'x' WHERE org_id = $1", [orgId])).rejects.toThrow(/append-only/);
    await expect(owner.query("DELETE FROM audit_events WHERE org_id = $1", [orgId])).rejects.toThrow(/append-only/);
  });
});

describe("tampering", () => {
  it("detects a changed event", async () => {
    const { token, orgId } = await org("Edit Co");
    await seal(token);
    await tamper("UPDATE audit_events SET actor_display = 'someone else' WHERE id = (SELECT id FROM audit_events WHERE org_id = $1 AND type = 'group.created' LIMIT 1)", [orgId]);
    const v = await integrity(token);
    expect(v).toMatchObject({ ok: false, problem: { block: 1, kind: "modified_or_missing" } });
  });

  it("detects a removed event", async () => {
    const { token, orgId } = await org("Delete Co");
    await seal(token);
    await tamper("DELETE FROM audit_events WHERE id = (SELECT id FROM audit_events WHERE org_id = $1 AND type = 'group.created' LIMIT 1)", [orgId]);
    expect((await integrity(token)).problem).toMatchObject({ block: 1, kind: "count" });
  });

  it("refuses to rewrite a sealed block", async () => {
    const { token, orgId } = await org("Block Co");
    await seal(token);
    await expect(owner.query("UPDATE audit_blocks SET digest = 'x' WHERE org_id = $1", [orgId])).rejects.toThrow(/append-only/);
  });

  it("raises a critical alert from the daily verification", async () => {
    const { token, orgId } = await org("Alarm Co");
    await seal(token);
    await tamper("UPDATE audit_events SET details = '{}' WHERE id = (SELECT id FROM audit_events WHERE org_id = $1 AND type = 'org.settings_updated' LIMIT 1)", [orgId]);
    const { enqueue } = await import("../src/platform/jobs.js");
    await h.deps.db.tenant(orgId, (tx) => enqueue(tx, orgId, "audit.verify", {}));
    await h.jobs.runOnce({ orgId });
    expect((await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token })).body.data[0]).toMatchObject({ title: "The audit log failed its integrity check", severity: "critical" });
    expect((await h.call("GET", "/v1/audit/events?type=audit.integrity_failed", { token })).body.data).toHaveLength(1);
  });
});

describe("retention", () => {
  it("removes whole blocks past retention, keeps the chain verifiable, and waits for destinations", async () => {
    const { token, orgId } = await org("Retain Co");
    expect((await h.call("PATCH", "/v1/org/settings", { token, body: { audit_retention_days: 10 } })).status).toBe(400);
    await h.call("PATCH", "/v1/org/settings", { token, body: { audit_retention_days: 30 } });
    const b1 = await seal(token);
    // A SIEM destination added now hasn't received anything after it yet.
    const dest = await h.call("POST", "/v1/event-destinations", { token, body: { kind: "webhook", name: "SIEM", url: "http://127.0.0.1:9/hook" } });
    expect(dest.status, JSON.stringify(dest.body)).toBe(201);
    await h.call("POST", "/v1/groups", { token, body: { name: "after the SIEM" } });
    const b2 = await seal(token);
    await owner.query("UPDATE audit_blocks SET last_ts = now() - interval '40 days' WHERE org_id = $1", [orgId]);

    const pruned = (await owner.query("SELECT * FROM nexus_prune_audit(100) WHERE org_id = $1", [orgId])).rows;
    // Block 1 predates the destination (its cursor starts after it); block 2 hasn't been delivered.
    expect(pruned.map((r) => Number(r.events))).toEqual([b1.events]);
    const v = await integrity(token);
    expect(v).toMatchObject({ ok: true, pruned_blocks: 1, blocks_checked: 1, retention_days: 30 });
    expect(b2.block).toBe(2);

    // Once delivered (the cursor moves past block 2), it goes too.
    await owner.query("UPDATE event_destinations SET cursor_txid = '999999999999', cursor_id = 'ffffffff-ffff-ffff-ffff-ffffffffffff' WHERE org_id = $1", [orgId]);
    await owner.query("SELECT * FROM nexus_prune_audit(100)");
    expect(await integrity(token)).toMatchObject({ ok: true, pruned_blocks: 2, blocks_checked: 0 });
  });
});

import type { Principal, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import type { Tx } from "../platform/db.js";
import { Conditions, evaluate, type Decision, type DeviceState, type Policy, type Subject } from "./engine.js";

export async function loadPolicies(tx: Tx): Promise<Policy[]> {
  const rows = await tx.selectFrom("access_policies").selectAll().orderBy("created_at").execute();
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    enabled: r.enabled,
    mode: r.mode,
    requirement: r.requirement,
    conditions: Conditions.parse(r.conditions),
  }));
}

export async function loadDevice(tx: Tx, deviceId: string | null): Promise<DeviceState | null> {
  if (!deviceId) return null;
  const d = await tx.selectFrom("devices").select(["id", "hostname", "status", "compliance", "last_seen_at"]).where("id", "=", deviceId).executeTakeFirst();
  if (!d) return null;
  const failing = await tx.selectFrom("device_checks").select("detail").where("device_id", "=", deviceId).where("status", "in", ["fail", "unknown"]).execute();
  return {
    id: d.id,
    hostname: d.hostname,
    active: d.status === "active",
    compliance: d.compliance,
    lastSeenAt: d.last_seen_at,
    failing: failing.map((f) => f.detail),
  };
}

export async function groupsOf(tx: Tx, userId: string) {
  const rows = await tx.selectFrom("group_members").select("group_id").where("user_id", "=", userId).execute();
  return new Set(rows.map((r) => r.group_id));
}

/**
 * How long a session's device proof lasts. After that the console asks the
 * agent again (silently, when it's running), so a copied session cookie
 * doesn't carry device trust forever.
 */
export const DEVICE_TRUST_TTL_MS = 12 * 3600_000;

/** The live subject for a sign-in from this session to this app. */
export async function subjectFor(tx: Tx, p: Principal, appId: string): Promise<Subject> {
  const session = await tx.selectFrom("sessions").select(["mfa_at", "device_id", "device_verified_at"]).where("id", "=", p.sessionId).executeTakeFirstOrThrow();
  return {
    userId: p.userId,
    groupIds: await groupsOf(tx, p.userId),
    appId,
    mfa: session.mfa_at !== null,
    device:
      session.device_verified_at && Date.now() - session.device_verified_at.getTime() < DEVICE_TRUST_TTL_MS ? await loadDevice(tx, session.device_id) : null,
  };
}

/**
 * Evaluates policies for an SSO sign-in and records report-only "would block"
 * results, so admins can see a policy's impact before enforcing it.
 */
export async function decideAccess(tx: Tx, p: Principal, app: { id: string; name: string }, meta: RequestMeta): Promise<Decision> {
  // Break-glass accounts are exempt: conditional access must never lock out the way back in.
  const bg = await tx.selectFrom("users").select("break_glass").where("id", "=", p.userId).executeTakeFirst();
  if (bg?.break_glass) return { outcome: "allow", reason: "Break-glass account: access policies don't apply", results: [] };
  const decision = evaluate(await loadPolicies(tx), await subjectFor(tx, p, app.id));
  for (const r of decision.results) {
    if (r.matched && r.satisfied === false && r.mode === "report_only") {
      await audit(tx, p.orgId, { principal: p, meta }, {
        type: "access.would_block",
        outcome: "denied",
        target: { type: "application", id: app.id, display: app.name },
        details: { policy_id: r.policy_id, policy: r.name, requirement: r.requirement, reason: r.reason },
      });
    }
  }
  return decision;
}

/** The matched policies, for the audit trail of a sign-in ("Why?"). */
export const matchedSummary = (d: Decision) =>
  d.results.filter((r) => r.matched).map((r) => ({ policy_id: r.policy_id, policy: r.name, mode: r.mode, requirement: r.requirement, satisfied: r.satisfied, reason: r.reason }));

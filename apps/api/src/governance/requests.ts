import { sql } from "kysely";
import type { Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { notifyUsers } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { conflict } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { enqueue, registerJobHandler, type JobRunner } from "../platform/jobs.js";
import { touchGroups, touchUsers } from "../provisioning/service.js";
import { assignedAppIds } from "../sso/apps.js";

/**
 * Access requests (JIT-01/02/04, OPS-11). A request moves through the catalog
 * entry's approval stages; the last approval grants the access (an app
 * assignment, a group membership or an admin role), which ends by itself when
 * its time is up. Every step is audited with the request ID, so request →
 * approvals → grant → end can be followed in the audit log.
 */

export type Stage = { kind: "manager" } | { kind: "users"; ids: string[] } | { kind: "group"; id: string } | { kind: "role"; role: string };
export type Eligible = { users: string[]; groups: string[] };
export type CatalogRow = {
  id: string;
  org_id: string;
  resource_type: "app" | "group" | "role";
  resource_id: string | null;
  role: string | null;
  max_hours: number;
  allow_permanent: boolean;
  stages: unknown;
  eligible: unknown;
  enabled: boolean;
};
export type RequestRow = {
  id: string;
  org_id: string;
  catalog_id: string;
  requester_id: string;
  justification: string;
  duration_hours: number | null;
  status: string;
  stage: number;
  expires_at: Date | null;
};

const stagesOf = (c: CatalogRow) => (Array.isArray(c.stages) ? (c.stages as Stage[]) : []);
const eligibleOf = (c: CatalogRow): Eligible => {
  const e = (c.eligible ?? {}) as Partial<Eligible>;
  return { users: e.users ?? [], groups: e.groups ?? [] };
};

/** What the request is for, in words. */
export async function resourceName(tx: Tx, c: Pick<CatalogRow, "resource_type" | "resource_id" | "role">) {
  if (c.resource_type === "role") return `${String(c.role).replace("_", " ")} role`;
  if (c.resource_type === "app") return (await tx.selectFrom("applications").select("name").where("id", "=", c.resource_id!).executeTakeFirst())?.name ?? "a removed app";
  return (await tx.selectFrom("groups").select("name").where("id", "=", c.resource_id!).executeTakeFirst())?.name ?? "a removed group";
}

const activeUsers = async (tx: Tx, ids: string[]) =>
  ids.length ? (await tx.selectFrom("users").select("id").where("id", "in", ids).where("status", "=", "active").execute()).map((u) => u.id) : [];

/** People who can decide a stage (never the requester). Falls back to access admins when the stage has nobody. */
export async function approversFor(tx: Tx, stage: Stage | undefined, requesterId: string): Promise<{ ids: string[]; fallback: boolean }> {
  let ids: string[] = [];
  if (stage?.kind === "manager") {
    const m = await tx.selectFrom("users").select("manager_id").where("id", "=", requesterId).executeTakeFirst();
    ids = m?.manager_id ? await activeUsers(tx, [m.manager_id]) : [];
  } else if (stage?.kind === "users") {
    ids = await activeUsers(tx, stage.ids);
  } else if (stage?.kind === "group") {
    ids = await activeUsers(tx, (await tx.selectFrom("group_members").select("user_id").where("group_id", "=", stage.id).execute()).map((m) => m.user_id));
  } else if (stage?.kind === "role") {
    ids = await activeUsers(tx, (await tx.selectFrom("user_roles").select("user_id").where("role", "=", stage.role).execute()).map((r) => r.user_id));
  }
  ids = ids.filter((id) => id !== requesterId);
  if (ids.length) return { ids, fallback: false };
  const admins = await activeUsers(tx, (await tx.selectFrom("user_roles").select("user_id").where("role", "in", ["owner", "admin"]).execute()).map((r) => r.user_id));
  return { ids: admins.filter((id) => id !== requesterId), fallback: true };
}

export async function isEligible(tx: Tx, c: CatalogRow, userId: string) {
  const e = eligibleOf(c);
  if (e.users.includes(userId)) return true;
  if (!e.groups.length) return false;
  return !!(await tx.selectFrom("group_members").select("user_id").where("user_id", "=", userId).where("group_id", "in", e.groups).executeTakeFirst());
}

/** Already has it (directly or through a group)? Then there's nothing to request, or to take away later. */
export async function alreadyHas(tx: Tx, c: CatalogRow, userId: string) {
  if (c.resource_type === "app") return (await assignedAppIds(tx, userId)).has(c.resource_id!);
  if (c.resource_type === "group") return !!(await tx.selectFrom("group_members").select("user_id").where("group_id", "=", c.resource_id!).where("user_id", "=", userId).executeTakeFirst());
  return !!(await tx.selectFrom("user_roles").select("role").where("user_id", "=", userId).where("role", "=", c.role!).executeTakeFirst());
}

async function requesterEmail(tx: Tx, id: string) {
  return (await tx.selectFrom("users").select("email").where("id", "=", id).executeTakeFirst())?.email ?? "someone";
}

/** Asks the approvers of the current stage. */
export async function notifyApprovers(tx: Tx, c: CatalogRow, req: RequestRow) {
  const stages = stagesOf(c);
  const { ids } = await approversFor(tx, stages[req.stage], req.requester_id);
  if (!ids.length) return;
  const who = await requesterEmail(tx, req.requester_id);
  const what = await resourceName(tx, c);
  await notifyUsers(tx, req.org_id, ids, {
    category: "access.approval",
    severity: c.resource_type === "role" ? "warning" : "info",
    title: `${who} requests ${what}`,
    body: `${req.justification}${req.duration_hours ? ` · for ${req.duration_hours} h` : " · permanently"}${stages.length > 1 ? ` · approval ${req.stage + 1} of ${stages.length}` : ""}`,
    entity: { type: "access_request", id: req.id },
    link: `/access-requests?view=approvals`,
  });
}

/** Gives the access and starts its clock. */
export async function grant(tx: Tx, c: CatalogRow, req: RequestRow, meta: RequestMeta, why: string) {
  const now = new Date();
  if (c.resource_type === "app") {
    await tx.insertInto("app_assignments").values({ org_id: req.org_id, app_id: c.resource_id!, principal_type: "user", principal_id: req.requester_id }).onConflict((oc) => oc.doNothing()).execute();
    await touchUsers(tx, req.org_id, [req.requester_id], [c.resource_id!]);
  } else if (c.resource_type === "group") {
    await tx.insertInto("group_members").values({ org_id: req.org_id, group_id: c.resource_id!, user_id: req.requester_id }).onConflict((oc) => oc.doNothing()).execute();
    await touchUsers(tx, req.org_id, [req.requester_id]);
    await touchGroups(tx, req.org_id, [c.resource_id!]);
  } else {
    await tx.insertInto("user_roles").values({ org_id: req.org_id, user_id: req.requester_id, role: c.role! }).onConflict((oc) => oc.doNothing()).execute();
  }
  const expires = req.duration_hours ? new Date(now.getTime() + req.duration_hours * 3600_000) : null;
  await tx.updateTable("access_requests").set({ status: "active", granted_at: now, expires_at: expires }).where("id", "=", req.id).execute();
  const what = await resourceName(tx, c);
  const email = await requesterEmail(tx, req.requester_id);
  await audit(tx, req.org_id, { meta }, {
    type: "access.granted",
    actor: { type: "system", id: null, display: "Access requests" },
    target: { type: "user", id: req.requester_id, display: email },
    details: { request_id: req.id, resource: { type: c.resource_type, id: c.resource_id, role: c.role, name: what }, until: expires?.toISOString() ?? null, why },
  });
  await notifyUsers(tx, req.org_id, [req.requester_id], {
    category: "access.granted",
    title: `You have ${what}${expires ? ` until ${expires.toUTCString().slice(0, 22)} UTC` : ""}`,
    body: why,
    entity: { type: "access_request", id: req.id },
    link: c.resource_type === "app" ? "/my-apps" : "/access-requests",
  });
}

/** Takes the access away again: its time ran out, or someone revoked it. */
export async function endGrant(tx: Tx, c: CatalogRow, req: RequestRow, meta: RequestMeta, how: { status: "ended" | "revoked"; reason: string; by?: { id: string; email: string } }) {
  if (c.resource_type === "app") {
    await tx.deleteFrom("app_assignments").where("app_id", "=", c.resource_id!).where("principal_type", "=", "user").where("principal_id", "=", req.requester_id).execute();
    await touchUsers(tx, req.org_id, [req.requester_id], [c.resource_id!]);
  } else if (c.resource_type === "group") {
    await tx.deleteFrom("group_members").where("group_id", "=", c.resource_id!).where("user_id", "=", req.requester_id).execute();
    await touchUsers(tx, req.org_id, [req.requester_id]);
    await touchGroups(tx, req.org_id, [c.resource_id!]);
  } else {
    await tx.deleteFrom("user_roles").where("user_id", "=", req.requester_id).where("role", "=", c.role!).execute();
  }
  await tx.updateTable("access_requests").set({ status: how.status, ended_at: new Date(), end_reason: how.reason }).where("id", "=", req.id).execute();
  const what = await resourceName(tx, c);
  const email = await requesterEmail(tx, req.requester_id);
  await audit(tx, req.org_id, { meta, display: how.by?.email }, {
    type: how.status === "ended" ? "access.expired" : "access.revoked",
    actor: how.by ? { type: "user", id: how.by.id, display: how.by.email } : { type: "system", id: null, display: "Access requests" },
    target: { type: "user", id: req.requester_id, display: email },
    details: { request_id: req.id, resource: { type: c.resource_type, id: c.resource_id, role: c.role, name: what }, reason: how.reason },
  });
  await notifyUsers(tx, req.org_id, [req.requester_id], {
    category: "access.ended",
    title: how.status === "ended" ? `Your access to ${what} ended` : `${how.by?.email ?? "An admin"} removed your access to ${what}`,
    body: how.reason,
    entity: { type: "access_request", id: req.id },
    link: "/access-requests",
  });
}

/** An approver's decision on the current stage. The last approval grants. */
export async function decide(tx: Tx, c: CatalogRow, req: RequestRow, approver: { id: string; email: string }, decision: "approve" | "deny", comment: string, meta: RequestMeta) {
  const stages = stagesOf(c);
  const { ids } = await approversFor(tx, stages[req.stage], req.requester_id);
  if (!ids.includes(approver.id)) throw conflict("not_an_approver", "You can't decide this request (or it's at another approval stage)");
  await tx.insertInto("access_decisions").values({ id: newId(), org_id: req.org_id, request_id: req.id, stage: req.stage, approver_id: approver.id, decision, comment }).execute();
  const what = await resourceName(tx, c);
  const email = await requesterEmail(tx, req.requester_id);
  await audit(tx, req.org_id, { meta }, {
    type: decision === "approve" ? "access.approved" : "access.denied",
    actor: { type: "user", id: approver.id, display: approver.email },
    target: { type: "user", id: req.requester_id, display: email },
    details: { request_id: req.id, stage: req.stage + 1, of: stages.length, resource: what, comment },
  });
  if (decision === "deny") {
    await tx.updateTable("access_requests").set({ status: "denied", ended_at: new Date(), end_reason: comment || `Denied by ${approver.email}` }).where("id", "=", req.id).execute();
    await notifyUsers(tx, req.org_id, [req.requester_id], { category: "access.denied", title: `${approver.email} denied your request for ${what}`, body: comment, entity: { type: "access_request", id: req.id }, link: "/access-requests" });
    return "denied" as const;
  }
  if (req.stage + 1 < stages.length) {
    const next = { ...req, stage: req.stage + 1 };
    await tx.updateTable("access_requests").set({ stage: next.stage }).where("id", "=", req.id).execute();
    await notifyApprovers(tx, c, next);
    return "next_stage" as const;
  }
  await grant(tx, c, req, meta, `Approved by ${approver.email}${comment ? `: ${comment}` : ""}`);
  return "granted" as const;
}

// ---- Expiry ----------------------------------------------------------------------------

const SWEEP_META: RequestMeta = { ip: "", userAgent: "nexus-access-expiry", requestId: "" };

registerJobHandler("access.expire", async (deps, job) => {
  await deps.db.tenant(job.org_id, async (tx) => {
    const req = await tx.selectFrom("access_requests").selectAll().where("id", "=", String((job.payload as { request_id: string }).request_id)).where("status", "=", "active").executeTakeFirst();
    if (!req || !req.expires_at || req.expires_at > new Date()) return;
    const c = await tx.selectFrom("access_catalog").selectAll().where("id", "=", req.catalog_id).executeTakeFirstOrThrow();
    await endGrant(tx, c, req, { ...SWEEP_META, requestId: job.id }, { status: "ended", reason: `Granted for ${req.duration_hours} h; the time is up` });
  });
});

/** Every minute: grants past their end are taken away. */
export function scheduleAccessExpiry(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 60_000) return;
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; request_id: string }>`SELECT * FROM nexus_access_grants_expired()`.execute(tx)).rows);
    for (const d of due) await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, "access.expire", { request_id: d.request_id }, { dedupeKey: `access.expire:${d.request_id}` }));
  });
}

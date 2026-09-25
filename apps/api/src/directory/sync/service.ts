import { sql } from "kysely";
import type { Deps, RequestMeta } from "../../context.js";
import { audit } from "../../audit/record.js";
import { notifyRoles } from "../../notify/send.js";
import type { Tx } from "../../platform/db.js";
import { newId } from "../../platform/ids.js";
import { enqueue, registerJobHandler, type JobRunner } from "../../platform/jobs.js";
import { issueInvitation, sendInvite, type PendingInvite } from "../invitations.js";
import { revokeUserSessions } from "../users.js";
import { touchGroups, touchUsers } from "../../provisioning/service.js";
import { emailAdmission } from "../../org/domains.js";
import { plan, PROVIDER_NAME, summarize, type Local, type Plan, type Remote } from "./plan.js";
import { fetchDirectory, ProviderError } from "./providers.js";

export const secretAad = (connectionId: string) => `directory_connection:${connectionId}`;

type Conn = {
  id: string;
  org_id: string;
  provider: "google" | "entra";
  name: string;
  config: unknown;
  secret: Buffer;
  enabled: boolean;
  sync_groups: boolean;
  group_filter: string[];
  deprovision: "suspend" | "none";
  invite_new_users: boolean;
  last_status: string;
};

export async function loadConnection(tx: Tx, id: string) {
  return (await tx.selectFrom("directory_connections").selectAll().where("id", "=", id).executeTakeFirst()) as Conn | undefined;
}

export function remoteFor(deps: Deps, conn: Pick<Conn, "id" | "provider" | "config" | "secret" | "sync_groups">): Promise<Remote> {
  const secret = deps.sealer.open(conn.secret, secretAad(conn.id)).toString();
  return fetchDirectory(deps.cfg, conn.provider, conn.config, secret, { groups: conn.sync_groups });
}

/** Local state visible to this connection (people and groups other directories manage are left to them). */
export async function loadLocal(tx: Tx, connectionId: string): Promise<Local> {
  const links = await tx.selectFrom("directory_links").select(["connection_id", "kind", "external_id", "local_id", "suspended_by_sync"]).execute();
  const foreign = new Set(links.filter((l) => l.connection_id !== connectionId).map((l) => `${l.kind}:${l.local_id}`));
  // Break-glass accounts are never managed by a directory: a bad sync must not lock the org out.
  const users = (await tx.selectFrom("users").select(["id", "email", "given_name", "family_name", "title", "department", "status", "break_glass"]).execute())
    .filter((u) => !foreign.has(`user:${u.id}`) && !u.break_glass)
    .map(({ break_glass: _b, ...u }) => u);
  const members = await tx.selectFrom("group_members").select(["group_id", "user_id"]).execute();
  const groups = (await tx.selectFrom("groups").select(["id", "name", "description"]).execute())
    .filter((g) => !foreign.has(`group:${g.id}`))
    .map((g) => ({ ...g, member_ids: members.filter((m) => m.group_id === g.id).map((m) => m.user_id) }));
  return { users, groups, links: links.filter((l) => l.connection_id === connectionId) };
}

export function planFor(conn: Conn, remote: Remote, local: Local) {
  return plan(remote, local, { provider: conn.provider, deprovision: conn.deprovision, sync_groups: conn.sync_groups, group_filter: conn.group_filter });
}

/** Applies a plan in the caller's transaction. Returns invitations to send after commit. */
export async function applyPlan(tx: Tx, conn: Conn, p: Plan, meta: RequestMeta) {
  const src = PROVIDER_NAME[conn.provider];
  const actor = { type: "system" as const, id: null, display: `${src} sync` };
  const skipped = [...p.skipped];
  const invites: PendingInvite[] = [];
  const userIds = new Map<string, string>(); // remote → local
  const groupIds = new Map<string, string>();
  for (const l of await tx.selectFrom("directory_links").select(["kind", "external_id", "local_id"]).where("connection_id", "=", conn.id).execute()) {
    (l.kind === "user" ? userIds : groupIds).set(l.external_id, l.local_id);
  }
  const link = async (kind: "user" | "group", external_id: string, local_id: string) => {
    await tx.insertInto("directory_links").values({ org_id: conn.org_id, connection_id: conn.id, kind, external_id, local_id }).onConflict((oc) => oc.doNothing()).execute();
    (kind === "user" ? userIds : groupIds).set(external_id, local_id);
  };
  const emailTaken = async (email: string) => (await sql<{ t: boolean }>`SELECT nexus_email_taken(${email}) AS t`.execute(tx)).rows[0]!.t;

  let created = 0;
  for (const r of p.create_users) {
    if (await emailTaken(r.email)) {
      skipped.push({ email: r.email, reason: "This email is already used by another Nexus organization" });
      continue;
    }
    const refused = await emailAdmission(tx, conn.org_id, r.email);
    if (refused) {
      skipped.push({ email: r.email, reason: refused });
      continue;
    }
    const id = newId();
    await tx
      .insertInto("users")
      .values({ id, org_id: conn.org_id, email: r.email, given_name: r.given_name, family_name: r.family_name, title: r.title, department: r.department, status: "staged", password_hash: null, attributes: "{}", updated_at: new Date() })
      .execute();
    await link("user", r.external_id, id);
    created++;
    if (conn.invite_new_users) invites.push(await issueInvitation(tx, { orgId: conn.org_id, userId: null }, id));
  }
  for (const l of p.link_users) await link("user", l.external_id, l.local_id);

  for (const u of p.update_users) {
    const set: Record<string, string> = {};
    for (const [f, ch] of Object.entries(u.changes)) set[f] = ch.to;
    if (set.email && (await emailTaken(set.email))) {
      skipped.push({ email: u.email, reason: `Can't change email to ${set.email}: it's already in use` });
      delete set.email;
    }
    const refused = set.email ? await emailAdmission(tx, conn.org_id, set.email) : null;
    if (refused) {
      skipped.push({ email: u.email, reason: `Can't change email to ${set.email}: ${refused}` });
      delete set.email;
    }
    if (Object.keys(set).length) await tx.updateTable("users").set({ ...set, updated_at: new Date() }).where("id", "=", u.local_id).execute();
  }

  for (const s of p.suspend_users) {
    await tx.updateTable("users").set({ status: "suspended", updated_at: new Date() }).where("id", "=", s.local_id).execute();
    const sessions = await revokeUserSessions(tx, s.local_id);
    await tx.updateTable("directory_links").set({ suspended_by_sync: true }).where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "=", s.local_id).execute();
    await audit(tx, conn.org_id, { meta }, { type: "user.suspended", actor, target: { type: "user", id: s.local_id, display: s.email }, details: { reason: s.reason, sessions_revoked: sessions, connection_id: conn.id } });
  }
  for (const r of p.reactivate_users) {
    const u = await tx.selectFrom("users").select("password_hash").where("id", "=", r.local_id).executeTakeFirstOrThrow();
    await tx.updateTable("users").set({ status: u.password_hash ? "active" : "staged", updated_at: new Date() }).where("id", "=", r.local_id).execute();
    await tx.updateTable("directory_links").set({ suspended_by_sync: false }).where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "=", r.local_id).execute();
    await audit(tx, conn.org_id, { meta }, { type: "user.activated", actor, target: { type: "user", id: r.local_id, display: r.email }, details: { reason: `Active again in ${src}`, connection_id: conn.id } });
  }

  // Groups.
  const names = new Set((await tx.selectFrom("groups").select("name").execute()).map((g) => g.name.toLowerCase()));
  const freeName = (name: string) => {
    let n = name;
    for (let i = 2; names.has(n.toLowerCase()); i++) n = `${name} (${i})`;
    names.add(n.toLowerCase());
    return n;
  };
  for (const g of p.create_groups) {
    const id = newId();
    await tx.insertInto("groups").values({ id, org_id: conn.org_id, name: freeName(g.name), description: g.description, updated_at: new Date() }).execute();
    await link("group", g.external_id, id);
  }
  for (const l of p.link_groups) await link("group", l.external_id, l.local_id);
  for (const g of p.update_groups) {
    const set: { name?: string; description?: string } = {};
    if (g.changes.name && !names.has(g.changes.name.to.toLowerCase())) {
      set.name = g.changes.name.to;
      names.add(set.name.toLowerCase());
    }
    if (g.changes.description) set.description = g.changes.description.to;
    if (Object.keys(set).length) await tx.updateTable("groups").set({ ...set, updated_at: new Date() }).where("id", "=", g.local_id).execute();
  }
  for (const m of p.membership) {
    const gid = groupIds.get(m.group_external_id);
    if (!gid) continue;
    const add = m.add.map((ext) => userIds.get(ext)).filter((x): x is string => !!x);
    if (add.length) await tx.insertInto("group_members").values(add.map((user_id) => ({ org_id: conn.org_id, group_id: gid, user_id }))).onConflict((oc) => oc.doNothing()).execute();
    if (m.remove.length) await tx.deleteFrom("group_members").where("group_id", "=", gid).where("user_id", "in", m.remove).execute();
  }

  // Everyone whose profile, status or groups changed: converge their app accounts.
  const affected = new Set<string>([
    ...p.create_users.map((r) => userIds.get(r.external_id)).filter((x): x is string => !!x),
    ...p.update_users.map((u) => u.local_id),
    ...p.suspend_users.map((u) => u.local_id),
    ...p.reactivate_users.map((u) => u.local_id),
    ...p.membership.flatMap((m) => [...m.add.map((ext) => userIds.get(ext)).filter((x): x is string => !!x), ...m.remove]),
  ]);
  await touchUsers(tx, conn.org_id, affected);
  await touchGroups(tx, conn.org_id, p.membership.map((m) => groupIds.get(m.group_external_id)).filter((x): x is string => !!x));
  const summary = { ...summarize(p), create_users: created, skipped: skipped.length };
  await audit(tx, conn.org_id, { meta }, { type: "directory.synced", actor, target: { type: "directory_connection", id: conn.id, display: conn.name }, details: summary });
  return { summary, skipped, invites };
}

const SYSTEM_META: RequestMeta = { ip: "", userAgent: "nexus-directory-sync", requestId: "" };

/** One sync run (the `directory.sync` job). */
export async function runSync(deps: Deps, orgId: string, connectionId: string, opts: { approvedSuspensions?: number; trigger?: string } = {}) {
  const conn = await deps.db.tenant(orgId, (tx) => loadConnection(tx, connectionId));
  if (!conn || (!conn.enabled && opts.trigger === "schedule")) return;
  const record = (tx: Tx, set: { last_status: "ok" | "error" | "needs_approval"; last_result?: unknown; last_error?: string }) =>
    tx
      .updateTable("directory_connections")
      .set({ last_status: set.last_status, last_result: JSON.stringify(set.last_result ?? {}), last_error: set.last_error ?? "", last_sync_at: new Date(), updated_at: new Date() })
      .where("id", "=", conn.id)
      .execute();

  let remote: Remote;
  try {
    remote = await remoteFor(deps, conn);
  } catch (err) {
    const message = err instanceof ProviderError ? err.message : `Couldn't read the directory: ${(err as Error).message}`;
    await deps.db.tenant(orgId, async (tx) => {
      await record(tx, { last_status: "error", last_error: message });
      if (conn.last_status !== "error") {
        await notifyRoles(tx, orgId, ["owner", "admin"], {
          category: "directory.sync",
          severity: "warning",
          title: `${conn.name} sync is failing`,
          body: message,
          entity: { type: "directory_connection", id: conn.id },
          link: `/directory-sync`,
        });
      }
    });
    if (err instanceof ProviderError && !err.permanent) throw err; // transient: let the job retry
    return;
  }

  const invites = await deps.db.tenant(orgId, async (tx) => {
    const p = planFor(conn, remote, await loadLocal(tx, conn.id));
    if (p.guard.tripped && (opts.approvedSuspensions ?? -1) < p.suspend_users.length) {
      await record(tx, {
        last_status: "needs_approval",
        last_result: { summary: summarize(p), guard: p.guard, suspend_users: p.suspend_users.slice(0, 200) },
      });
      if (conn.last_status !== "needs_approval") {
        await notifyRoles(tx, orgId, ["owner", "admin"], {
          category: "directory.sync",
          severity: "warning",
          title: `${conn.name} sync wants to suspend ${p.suspend_users.length} people`,
          body: `That's more than the safety limit of ${p.guard.threshold}, so nothing was changed. Review and approve it, or fix the directory scope.`,
          entity: { type: "directory_connection", id: conn.id },
          link: `/directory-sync`,
        });
      }
      return [];
    }
    const out = await applyPlan(tx, conn, p, SYSTEM_META);
    await record(tx, { last_status: "ok", last_result: { summary: out.summary, skipped: out.skipped.slice(0, 200) } });
    return out.invites;
  });
  await Promise.allSettled(invites.map((inv) => sendInvite(deps, inv)));
}

registerJobHandler("directory.sync", async (deps, job) => {
  const p = job.payload as { connection_id: string; approved_suspensions?: number; trigger?: string };
  await runSync(deps, job.org_id, p.connection_id, { approvedSuspensions: p.approved_suspensions, trigger: p.trigger });
});

export const syncDedupeKey = (id: string) => `directory.sync:${id}`;

/** Enqueue scheduled syncs once a minute. */
export function scheduleDirectorySyncs(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 60_000) return;
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; connection_id: string }>`SELECT * FROM nexus_due_directory_syncs()`.execute(tx)).rows);
    for (const d of due) {
      await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, "directory.sync", { connection_id: d.connection_id, trigger: "schedule" }, { dedupeKey: syncDedupeKey(d.connection_id), maxAttempts: 3 }));
    }
  });
}

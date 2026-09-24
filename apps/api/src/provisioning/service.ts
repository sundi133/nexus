import { createHash } from "node:crypto";
import { sql } from "kysely";
import type { Deps } from "../context.js";
import { notifyRoles } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { enqueue, registerJobHandler, type JobRunner } from "../platform/jobs.js";
import { ScimClient, ScimError, scimUser } from "./scim-client.js";

/**
 * Outbound provisioning (SCIM-01/02). Desired state is derived, never stored:
 * a person should have an active account in an app iff they're assigned to it
 * (directly or through a group) and their Nexus account is active or staged.
 * Anything that might change that "touches" the person; a job then converges
 * the app to it. A periodic reconcile catches anything a touch missed.
 */

export const tokenAad = (appId: string) => `app_provisioning:${appId}`;

const enabledApps = async (tx: Tx) => (await tx.selectFrom("app_provisioning").select(["app_id", "push_groups"]).where("enabled", "=", true).execute());

/** People changed (profile, status, groups, assignments): converge their accounts in every provisioned app. */
export async function touchUsers(tx: Tx, orgId: string, userIds: Iterable<string>, apps?: string[]) {
  const ids = [...new Set(userIds)];
  if (!ids.length) return;
  for (const a of await enabledApps(tx)) {
    if (apps && !apps.includes(a.app_id)) continue;
    for (const user_id of ids) {
      await enqueue(tx, orgId, "scim.user", { app_id: a.app_id, user_id }, { dedupeKey: `scim.user:${a.app_id}:${user_id}` });
    }
  }
}

/** Groups changed (members, name, assignment, deletion): converge pushed groups. */
export async function touchGroups(tx: Tx, orgId: string, groupIds: Iterable<string>, apps?: string[]) {
  const ids = [...new Set(groupIds)];
  if (!ids.length) return;
  for (const a of await enabledApps(tx)) {
    if (!a.push_groups || (apps && !apps.includes(a.app_id))) continue;
    for (const group_id of ids) {
      await enqueue(tx, orgId, "scim.group", { app_id: a.app_id, group_id }, { dedupeKey: `scim.group:${a.app_id}:${group_id}` });
    }
  }
}

/** Everyone who is or should be in an app. */
export async function touchApp(tx: Tx, orgId: string, appId: string) {
  const assigned = await tx.selectFrom("app_assignments").select(["principal_type", "principal_id"]).where("app_id", "=", appId).execute();
  const groupIds = assigned.filter((a) => a.principal_type === "group").map((a) => a.principal_id);
  const members = groupIds.length ? await tx.selectFrom("group_members").select("user_id").where("group_id", "in", groupIds).execute() : [];
  const existing = await tx.selectFrom("provisioned_accounts").select("user_id").where("app_id", "=", appId).execute();
  await touchUsers(tx, orgId, [...assigned.filter((a) => a.principal_type === "user").map((a) => a.principal_id), ...members.map((m) => m.user_id), ...existing.map((e) => e.user_id)], [appId]);
  const pushed = await tx.selectFrom("provisioned_groups").select("group_id").where("app_id", "=", appId).execute();
  await touchGroups(tx, orgId, [...groupIds, ...pushed.map((g) => g.group_id)], [appId]);
}

/** People affected by an assignment change on an app. */
export async function touchAssignment(tx: Tx, orgId: string, appId: string, principals: { principal_type: "user" | "group"; principal_id: string }[]) {
  const groupIds = principals.filter((p) => p.principal_type === "group").map((p) => p.principal_id);
  const members = groupIds.length ? await tx.selectFrom("group_members").select("user_id").where("group_id", "in", groupIds).execute() : [];
  await touchUsers(tx, orgId, [...principals.filter((p) => p.principal_type === "user").map((p) => p.principal_id), ...members.map((m) => m.user_id)], [appId]);
  await touchGroups(tx, orgId, groupIds, [appId]);
}

async function isAssigned(tx: Tx, appId: string, userId: string) {
  const r = await tx
    .selectFrom("app_assignments")
    .select("app_id")
    .where("app_id", "=", appId)
    .where((eb) =>
      eb.or([
        eb.and([eb("principal_type", "=", "user"), eb("principal_id", "=", userId)]),
        eb.and([eb("principal_type", "=", "group"), eb("principal_id", "in", eb.selectFrom("group_members").select("group_id").where("user_id", "=", userId))]),
      ]),
    )
    .executeTakeFirst();
  return !!r;
}

async function clientFor(deps: Deps, tx: Tx, appId: string) {
  const prov = await tx.selectFrom("app_provisioning").selectAll().where("app_id", "=", appId).executeTakeFirst();
  if (!prov?.enabled) return null;
  return { prov, client: new ScimClient(prov.base_url, deps.sealer.open(prov.token, tokenAad(appId)).toString()) };
}

/** Records an app-level failure (bad token, unreachable) and tells admins once. */
async function appFailed(deps: Deps, orgId: string, appId: string, err: ScimError) {
  await deps.db.tenant(orgId, async (tx) => {
    const before = await tx.selectFrom("app_provisioning").select("last_error").where("app_id", "=", appId).executeTakeFirst();
    await tx.updateTable("app_provisioning").set({ last_error: err.message, last_error_at: new Date() }).where("app_id", "=", appId).execute();
    if (before && !before.last_error) {
      const app = await tx.selectFrom("applications").select("name").where("id", "=", appId).executeTakeFirst();
      await notifyRoles(tx, orgId, ["owner", "admin"], {
        category: "apps.provisioning",
        severity: "warning",
        title: `Provisioning to ${app?.name ?? "an app"} is failing`,
        body: err.message,
        entity: { type: "application", id: appId },
        link: `/apps/${appId}`,
      });
    }
  });
}

async function appOk(tx: Tx, appId: string) {
  await tx.updateTable("app_provisioning").set({ last_error: "", last_error_at: null, last_success_at: new Date() }).where("app_id", "=", appId).execute();
}

const hash = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex").slice(0, 32);

export async function syncUser(deps: Deps, orgId: string, appId: string, userId: string) {
  const state = await deps.db.tenant(orgId, async (tx) => {
    const c = await clientFor(deps, tx, appId);
    if (!c) return null;
    const user = await tx.selectFrom("users").select(["id", "email", "given_name", "family_name", "title", "department", "status"]).where("id", "=", userId).executeTakeFirst();
    const account = await tx.selectFrom("provisioned_accounts").selectAll().where("app_id", "=", appId).where("user_id", "=", userId).executeTakeFirst();
    const desired = !!user && (user.status === "active" || user.status === "staged") && (await isAssigned(tx, appId, userId));
    return { ...c, user, account, desired };
  });
  if (!state) return;
  const { client, prov, user, account, desired } = state;
  const save = (row: { remote_id: string | null; state: "active" | "inactive" | "error"; attrs_hash?: string; last_error?: string }) =>
    deps.db.tenant(orgId, async (tx) => {
      await tx
        .insertInto("provisioned_accounts")
        .values({ org_id: orgId, app_id: appId, user_id: userId, remote_id: row.remote_id, state: row.state, attrs_hash: row.attrs_hash ?? "", last_error: row.last_error ?? "", last_synced_at: new Date() })
        .onConflict((oc) =>
          oc.columns(["app_id", "user_id"]).doUpdateSet({ remote_id: row.remote_id, state: row.state, ...(row.attrs_hash !== undefined ? { attrs_hash: row.attrs_hash } : {}), last_error: row.last_error ?? "", last_synced_at: new Date() }),
        )
        .execute();
      if (row.state !== "error") await appOk(tx, appId);
    });

  try {
    if (desired && user) {
      const attrs = scimUser(user);
      const h = hash(attrs);
      let remoteId = account?.remote_id ?? null;
      let created = false;
      if (remoteId) {
        if (account!.state === "active" && account!.attrs_hash === h) return; // nothing to send
        try {
          await client.updateUser(remoteId, attrs, true);
        } catch (err) {
          if (!(err instanceof ScimError && err.status === 404)) throw err;
          remoteId = null; // deleted in the app: create it again
        }
      }
      if (!remoteId) {
        try {
          remoteId = await client.createUser(attrs);
          created = true;
        } catch (err) {
          if (!(err instanceof ScimError && err.status === 409)) throw err;
          // The app already has this person: adopt the account instead of failing.
          remoteId = await client.findUser(attrs.userName);
          if (!remoteId) throw err;
          await client.updateUser(remoteId, attrs, true);
        }
      }
      await save({ remote_id: remoteId, state: "active", attrs_hash: h });
      if (created && prov.push_groups) {
        // Groups pushed before this account existed need it as a member now.
        await deps.db.tenant(orgId, async (tx) => {
          const groups = await tx.selectFrom("group_members").select("group_id").where("user_id", "=", userId).execute();
          await touchGroups(tx, orgId, groups.map((g) => g.group_id), [appId]);
        });
      }
    } else if (account?.remote_id && account.state !== "inactive") {
      if (prov.on_unassign === "delete") {
        await client.deleteUser(account.remote_id).catch((err) => {
          if (!(err instanceof ScimError && err.status === 404)) throw err;
        });
        await deps.db.tenant(orgId, async (tx) => {
          await tx.deleteFrom("provisioned_accounts").where("app_id", "=", appId).where("user_id", "=", userId).execute();
          await appOk(tx, appId);
        });
      } else {
        await client.setActive(account.remote_id, false).catch((err) => {
          if (!(err instanceof ScimError && err.status === 404)) throw err; // already gone upstream: fine
        });
        await save({ remote_id: account.remote_id, state: "inactive" });
      }
    }
  } catch (err) {
    if (!(err instanceof ScimError)) throw err;
    await save({ remote_id: account?.remote_id ?? null, state: "error", last_error: err.message });
    if (err.status === 401 || err.status === 403 || err.status === 0) await appFailed(deps, orgId, appId, err);
    if (err.retryable) throw err;
  }
}

export async function syncGroup(deps: Deps, orgId: string, appId: string, groupId: string) {
  const state = await deps.db.tenant(orgId, async (tx) => {
    const c = await clientFor(deps, tx, appId);
    if (!c || !c.prov.push_groups) return null;
    const group = await tx.selectFrom("groups").select(["id", "name"]).where("id", "=", groupId).executeTakeFirst();
    const assigned = !!(await tx.selectFrom("app_assignments").select("app_id").where("app_id", "=", appId).where("principal_type", "=", "group").where("principal_id", "=", groupId).executeTakeFirst());
    const pushed = await tx.selectFrom("provisioned_groups").selectAll().where("app_id", "=", appId).where("group_id", "=", groupId).executeTakeFirst();
    const members = group
      ? await tx
          .selectFrom("group_members")
          .innerJoin("provisioned_accounts", (j) => j.onRef("provisioned_accounts.user_id", "=", "group_members.user_id").on("provisioned_accounts.app_id", "=", appId))
          .select("provisioned_accounts.remote_id")
          .where("group_members.group_id", "=", groupId)
          .where("provisioned_accounts.state", "=", "active")
          .execute()
      : [];
    return { ...c, group, assigned, pushed, memberIds: members.map((m) => m.remote_id).filter((x): x is string => !!x).sort() };
  });
  if (!state) return;
  const { client, group, assigned, pushed, memberIds } = state;
  try {
    if (group && assigned) {
      let remoteId = pushed?.remote_id ?? null;
      if (remoteId) {
        try {
          await client.updateGroup(remoteId, group.name, memberIds);
        } catch (err) {
          if (!(err instanceof ScimError && err.status === 404)) throw err;
          remoteId = null;
        }
      }
      if (!remoteId) remoteId = await client.createGroup(group.name, memberIds);
      await deps.db.tenant(orgId, async (tx) => {
        await tx
          .insertInto("provisioned_groups")
          .values({ org_id: orgId, app_id: appId, group_id: groupId, remote_id: remoteId!, display_name: group.name, last_synced_at: new Date() })
          .onConflict((oc) => oc.columns(["app_id", "group_id"]).doUpdateSet({ remote_id: remoteId!, display_name: group.name, last_synced_at: new Date() }))
          .execute();
        await appOk(tx, appId);
      });
    } else if (pushed) {
      await client.deleteGroup(pushed.remote_id).catch((err) => {
        if (!(err instanceof ScimError && err.status === 404)) throw err;
      });
      await deps.db.tenant(orgId, (tx) => tx.deleteFrom("provisioned_groups").where("app_id", "=", appId).where("group_id", "=", groupId).execute());
    }
  } catch (err) {
    if (!(err instanceof ScimError)) throw err;
    if (err.status === 401 || err.status === 403 || err.status === 0) await appFailed(deps, orgId, appId, err);
    if (err.retryable) throw err;
    console.warn(`[scim] group ${groupId} → app ${appId}: ${err.message}`);
  }
}

registerJobHandler("scim.user", async (deps, job) => {
  const p = job.payload as { app_id: string; user_id: string };
  await syncUser(deps, job.org_id, p.app_id, p.user_id);
});
registerJobHandler("scim.group", async (deps, job) => {
  const p = job.payload as { app_id: string; group_id: string };
  await syncGroup(deps, job.org_id, p.app_id, p.group_id);
});
registerJobHandler("scim.reconcile", async (deps, job) => {
  const p = job.payload as { app_id: string };
  await deps.db.tenant(job.org_id, (tx) => touchApp(tx, job.org_id, p.app_id));
});

const RECONCILE_MS = 6 * 3600_000;

/** Every 6 hours, reconcile every provisioned app (safety net for missed triggers and upstream drift). */
export function scheduleProvisioningReconcile(jobs: JobRunner, deps: Deps) {
  let last = Date.now(); // not at boot: the first run comes after one interval
  jobs.onTick(async () => {
    if (Date.now() - last < RECONCILE_MS) return;
    last = Date.now();
    const apps = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; app_id: string }>`SELECT * FROM nexus_provisioned_apps()`.execute(tx)).rows);
    for (const a of apps) {
      await deps.db.tenant(a.org_id, (tx) => enqueue(tx, a.org_id, "scim.reconcile", { app_id: a.app_id }, { dedupeKey: `scim.reconcile:${a.app_id}` }));
    }
  });
}

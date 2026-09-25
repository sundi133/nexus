import { Hono, type Context } from "hono";
import { sql } from "kysely";
import type { App, Deps, Env, RequestMeta } from "../../context.js";
import { audit } from "../../audit/record.js";
import { RateLimiter } from "../../auth/ratelimit.js";
import { hashToken } from "../../auth/tokens.js";
import { idpForEmail } from "../../federation/enforce.js";
import { notifyRoles } from "../../notify/send.js";
import { emailAdmission } from "../../org/domains.js";
import type { Tx } from "../../platform/db.js";
import { isUniqueViolation } from "../../platform/db.js";
import { ApiError } from "../../platform/errors.js";
import { newId } from "../../platform/ids.js";
import { touchGroups, touchUsers } from "../../provisioning/service.js";
import { issueInvitation, sendInvite, type PendingInvite } from "../invitations.js";
import { offboard } from "../offboarding.js";
import { revokeUserSessions } from "../users.js";
import {
  groupChanges,
  matches,
  parseFilter,
  patchOps,
  patchUser,
  SCHEMA,
  ScimError,
  simpleEq,
  toScimGroup,
  toScimUser,
  userFields,
  type LocalUser,
  type UserFields,
} from "./resources.js";

/**
 * Inbound SCIM 2.0 service provider (DIR-07): Okta, Entra ID, JumpCloud,
 * OneLogin… push users and groups into Nexus. Authenticated by the
 * connection's bearer token; everything happens inside that organization.
 *
 * Same rules as a synced directory: break-glass accounts are invisible,
 * deactivation follows the connection's deprovisioning setting, a reactivation
 * only undoes a suspension this source made, and a burst of deactivations is
 * held until an admin approves it.
 */

type Conn = { id: string; org_id: string; name: string; deprovision: "suspend" | "none"; invite_new_users: boolean; deactivations_allowed_until: Date | null };
type ScimEnv = { Variables: Env["Variables"] & { conn: Conn } };
type C = Context<ScimEnv>;

const CONTENT_TYPE = "application/scim+json";
const limiter = new RateLimiter(1200, 60_000); // per connection
const lastSeen = new Map<string, number>();
const MAX_PAGE = 200;

class GuardTripped extends Error {
  constructor(readonly recent: number, readonly threshold: number) {
    super("deactivation guard");
  }
}

const actorOf = (conn: Conn) => ({ type: "system" as const, id: null, display: `SCIM · ${conn.name}` });
const scimJson = (c: C, body: unknown, status: 200 | 201 = 200) => c.body(JSON.stringify(body), status, { "content-type": CONTENT_TYPE });
const base = (deps: Deps) => `${deps.cfg.apiPublicUrl}/scim/v2`;

async function body(c: C): Promise<Record<string, any>> {
  try {
    const b = await c.req.json();
    if (!b || typeof b !== "object") throw new Error();
    return b;
  } catch {
    throw new ScimError(400, "The body must be a JSON object", "invalidSyntax");
  }
}

function page(c: C) {
  const startIndex = Math.max(1, Number(c.req.query("startIndex") ?? 1) || 1);
  const count = Math.min(MAX_PAGE, Math.max(0, Number(c.req.query("count") ?? 100) || 0));
  return { startIndex, count };
}
const listResponse = (all: unknown[], p: { startIndex: number; count: number }) => ({
  schemas: [SCHEMA.list],
  totalResults: all.length,
  itemsPerPage: Math.min(p.count, Math.max(0, all.length - (p.startIndex - 1))),
  startIndex: p.startIndex,
  Resources: all.slice(p.startIndex - 1, p.startIndex - 1 + p.count),
});

// ---- Users ------------------------------------------------------------------------------

const userCols = ["users.id", "users.email", "users.given_name", "users.family_name", "users.title", "users.department", "users.status", "users.created_at", "users.updated_at"] as const;
/** People SCIM can see: everyone but break-glass accounts and the deprovisioned. */
const visibleUsers = (tx: Tx) => tx.selectFrom("users").select(userCols).where("users.break_glass", "=", false).where("users.status", "<>", "deprovisioned");

async function scimUsers(tx: Tx, deps: Deps, conn: Conn, users: LocalUser[]) {
  if (!users.length) return [];
  const ids = users.map((u) => u.id);
  const links = await tx.selectFrom("directory_links").select(["local_id", "external_id"]).where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "in", ids).execute();
  const groups = await tx.selectFrom("group_members").innerJoin("groups", "groups.id", "group_members.group_id").select(["group_members.user_id", "groups.id", "groups.name"]).where("group_members.user_id", "in", ids).execute();
  const ext = new Map(links.map((l) => [l.local_id, l.external_id]));
  return users.map((u) =>
    toScimUser(u, { externalId: ext.get(u.id) === u.id ? null : (ext.get(u.id) ?? null), groups: groups.filter((g) => g.user_id === u.id).map((g) => ({ id: g.id, name: g.name })), base: base(deps) }),
  );
}

async function findUser(tx: Tx, id: string) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return undefined;
  return visibleUsers(tx).where("users.id", "=", id).executeTakeFirst();
}

async function link(tx: Tx, conn: Conn, kind: "user" | "group", localId: string, externalId: string | null) {
  const ext = externalId || localId;
  const existing = await tx.selectFrom("directory_links").select("external_id").where("connection_id", "=", conn.id).where("kind", "=", kind).where("local_id", "=", localId).executeTakeFirst();
  if (!existing) {
    await tx.insertInto("directory_links").values({ org_id: conn.org_id, connection_id: conn.id, kind, external_id: ext, local_id: localId }).execute();
  } else if (externalId && existing.external_id !== externalId) {
    await tx.updateTable("directory_links").set({ external_id: externalId }).where("connection_id", "=", conn.id).where("kind", "=", kind).where("local_id", "=", localId).execute();
  }
}

/** Refuses a burst of deactivations: more than max(5, 10% of people) in an hour needs an admin's approval. */
async function checkDeactivationGuard(tx: Tx, conn: Conn) {
  if (conn.deactivations_allowed_until && conn.deactivations_allowed_until > new Date()) return;
  const recent = Number(
    (
      await sql<{ n: number }>`
        SELECT count(*)::int AS n FROM audit_events
        WHERE org_id = ${conn.org_id} AND ts > now() - interval '1 hour'
          AND type IN ('user.suspended', 'user.offboarded') AND details->>'connection_id' = ${conn.id}`.execute(tx)
    ).rows[0]!.n,
  );
  const total = Number((await tx.selectFrom("users").select((eb) => eb.fn.countAll<number>().as("n")).where("status", "in", ["active", "staged"]).executeTakeFirstOrThrow()).n);
  const threshold = Math.max(5, Math.ceil(total * 0.1));
  if (recent >= threshold) throw new GuardTripped(recent, threshold);
}

async function applyUser(tx: Tx, deps: Deps, meta: RequestMeta, conn: Conn, before: LocalUser | undefined, f: UserFields): Promise<{ id: string; invite?: PendingInvite }> {
  const actor = actorOf(conn);
  const who = { meta, display: actor.display };
  const detailsBase = { connection_id: conn.id, via: "scim" };
  const emailProblem = async (email: string) => {
    const other = await tx.selectFrom("users").select("id").where(sql`lower(email)`, "=", email).where("status", "<>", "deprovisioned").executeTakeFirst();
    if (other && other.id !== before?.id) return new ScimError(409, `${email} already belongs to another person in this organization`, "uniqueness");
    const taken = (await sql<{ t: boolean }>`SELECT nexus_email_taken(${email}) AS t`.execute(tx)).rows[0]!.t;
    if (taken && !other) return new ScimError(409, `${email} is already used by another Nexus organization`, "uniqueness");
    const refused = await emailAdmission(tx, conn.org_id, email);
    return refused ? new ScimError(400, refused, "invalidValue") : null;
  };

  if (!before) {
    const problem = await emailProblem(f.email);
    if (problem) throw problem;
    const id = newId();
    // Staged until they sign in: through the org's IdP when one covers their domain, else with an invitation.
    await tx
      .insertInto("users")
      .values({ id, org_id: conn.org_id, email: f.email, given_name: f.given_name, family_name: f.family_name, title: f.title, department: f.department, status: f.active ? "staged" : "suspended", password_hash: null, attributes: "{}", updated_at: new Date() })
      .execute();
    await link(tx, conn, "user", id, f.external_id);
    if (!f.active) await tx.updateTable("directory_links").set({ suspended_by_sync: true }).where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "=", id).execute();
    await audit(tx, conn.org_id, who, { type: "user.created", actor, target: { type: "user", id, display: f.email }, details: { ...detailsBase, active: f.active } });
    await touchUsers(tx, conn.org_id, [id]);
    const federated = await idpForEmail(deps, f.email);
    const invite = f.active && conn.invite_new_users && !(federated && federated.org_id === conn.org_id) ? await issueInvitation(tx, { orgId: conn.org_id, userId: null }, id) : undefined;
    return { id, invite };
  }

  const id = before.id;
  await link(tx, conn, "user", id, f.external_id);
  const changes: Record<string, { from: string; to: string }> = {};
  for (const k of ["email", "given_name", "family_name", "title", "department"] as const) if (f[k] !== before[k]) changes[k] = { from: before[k], to: f[k] };
  if (changes.email) {
    const problem = await emailProblem(f.email);
    if (problem) throw problem;
  }
  if (Object.keys(changes).length) {
    await tx.updateTable("users").set({ ...Object.fromEntries(Object.entries(changes).map(([k, v]) => [k, v.to])), updated_at: new Date() }).where("id", "=", id).execute();
    await audit(tx, conn.org_id, who, { type: "user.updated", actor, target: { type: "user", id, display: f.email }, details: { ...detailsBase, changes } });
  }

  const wasActive = before.status === "active" || before.status === "staged";
  if (wasActive && !f.active && conn.deprovision === "suspend") {
    await checkDeactivationGuard(tx, conn);
    await tx.updateTable("users").set({ status: "suspended", updated_at: new Date() }).where("id", "=", id).execute();
    const sessions = await revokeUserSessions(tx, id);
    await tx.updateTable("directory_links").set({ suspended_by_sync: true }).where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "=", id).execute();
    await audit(tx, conn.org_id, who, { type: "user.suspended", actor, target: { type: "user", id, display: f.email }, details: { ...detailsBase, reason: `Deactivated in ${conn.name}`, sessions_revoked: sessions } });
  } else if (!wasActive && f.active && before.status === "suspended") {
    // Only undo a suspension this source made; an admin's suspension stands.
    const l = await tx.selectFrom("directory_links").select("suspended_by_sync").where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "=", id).executeTakeFirst();
    if (l?.suspended_by_sync) {
      const u = await tx.selectFrom("users").select("password_hash").where("id", "=", id).executeTakeFirstOrThrow();
      await tx.updateTable("users").set({ status: u.password_hash ? "active" : "staged", updated_at: new Date() }).where("id", "=", id).execute();
      await tx.updateTable("directory_links").set({ suspended_by_sync: false }).where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "=", id).execute();
      await audit(tx, conn.org_id, who, { type: "user.activated", actor, target: { type: "user", id, display: f.email }, details: { ...detailsBase, reason: `Active again in ${conn.name}` } });
    }
  }
  await touchUsers(tx, conn.org_id, [id]);
  return { id };
}

// ---- Groups -----------------------------------------------------------------------------

async function scimGroup(tx: Tx, deps: Deps, conn: Conn, g: { id: string; name: string; created_at: Date; updated_at: Date }, withMembers: boolean) {
  const l = await tx.selectFrom("directory_links").select("external_id").where("connection_id", "=", conn.id).where("kind", "=", "group").where("local_id", "=", g.id).executeTakeFirst();
  const members = withMembers
    ? await tx
        .selectFrom("group_members")
        .innerJoin("users", "users.id", "group_members.user_id")
        .select(["users.id", "users.email"])
        .where("group_members.group_id", "=", g.id)
        .where("users.break_glass", "=", false)
        .where("users.status", "<>", "deprovisioned")
        .execute()
    : null;
  return toScimGroup(g, { externalId: l && l.external_id !== g.id ? l.external_id : null, members, base: base(deps) });
}

async function setMembers(tx: Tx, conn: Conn, groupId: string, ch: { add: string[]; remove: string[]; replace?: string[] }) {
  const valid = async (ids: string[]) =>
    ids.length ? (await visibleUsers(tx).where("users.id", "in", ids.filter((x) => /^[0-9a-f-]{36}$/i.test(x))).execute()).map((u) => u.id) : [];
  const current = (await tx.selectFrom("group_members").select("user_id").where("group_id", "=", groupId).execute()).map((m) => m.user_id);
  let add = await valid(ch.add);
  let remove = ch.remove;
  if (ch.replace) {
    const want = new Set(await valid(ch.replace));
    add = [...want].filter((x) => !current.includes(x));
    remove = current.filter((x) => !want.has(x));
  }
  add = add.filter((x) => !current.includes(x));
  remove = remove.filter((x) => current.includes(x));
  if (add.length) await tx.insertInto("group_members").values(add.map((user_id) => ({ org_id: conn.org_id, group_id: groupId, user_id }))).onConflict((oc) => oc.doNothing()).execute();
  if (remove.length) await tx.deleteFrom("group_members").where("group_id", "=", groupId).where("user_id", "in", remove).execute();
  if (add.length || remove.length) {
    await touchUsers(tx, conn.org_id, [...add, ...remove]);
    await touchGroups(tx, conn.org_id, [groupId]);
  }
  return { added: add.length, removed: remove.length };
}

async function findGroup(tx: Tx, id: string) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return undefined;
  return tx.selectFrom("groups").select(["id", "name", "created_at", "updated_at"]).where("id", "=", id).executeTakeFirst();
}

async function renameGroup(tx: Tx, groupId: string, name: string) {
  const n = name.trim().slice(0, 200);
  if (!n) throw new ScimError(400, "displayName is required", "invalidValue");
  const clash = await tx.selectFrom("groups").select("id").where(sql`lower(name)`, "=", n.toLowerCase()).where("id", "<>", groupId).executeTakeFirst();
  if (clash) throw new ScimError(409, `A group named "${n}" already exists`, "uniqueness");
  await tx.updateTable("groups").set({ name: n, updated_at: new Date() }).where("id", "=", groupId).execute();
}

// ---- The server -------------------------------------------------------------------------

export function registerScimServer(app: App) {
  const scim = new Hono<ScimEnv>();

  scim.use("*", async (c, next) => {
    const deps = c.get("deps");
    const auth = c.req.header("authorization") ?? "";
    const token = /^Bearer\s+(\S+)$/i.exec(auth)?.[1];
    const found = token
      ? await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; connection_id: string; enabled: boolean }>`SELECT * FROM nexus_scim_auth(${hashToken(token)})`.execute(tx)).rows[0])
      : undefined;
    if (!found) throw new ScimError(401, "A valid SCIM bearer token is required");
    if (!found.enabled) throw new ScimError(403, "This SCIM connection is turned off in Nexus");
    if (!limiter.take(found.connection_id)) throw new ScimError(429, "Too many requests. Slow down and retry.");
    const conn = await deps.db.tenant(found.org_id, (tx) =>
      tx.selectFrom("directory_connections").select(["id", "org_id", "name", "deprovision", "invite_new_users", "deactivations_allowed_until"]).where("id", "=", found.connection_id).executeTakeFirstOrThrow(),
    );
    c.set("conn", conn as Conn);
    if (Date.now() - (lastSeen.get(conn.id) ?? 0) > 60_000) {
      lastSeen.set(conn.id, Date.now());
      await deps.db.tenant(conn.org_id, (tx) => tx.updateTable("directory_connections").set({ last_request_at: new Date() }).where("id", "=", conn.id).execute());
    }
    await next();
  });

  /** Runs a change; a tripped deactivation guard is recorded (and admins alerted) in its own transaction. */
  const mutate = async <T>(c: C, fn: (tx: Tx) => Promise<T>): Promise<T> => {
    const deps = c.get("deps");
    const conn = c.get("conn");
    try {
      return await deps.db.tenant(conn.org_id, fn);
    } catch (err) {
      if (!(err instanceof GuardTripped)) throw err;
      await deps.db.tenant(conn.org_id, async (tx) => {
        const r = await tx
          .updateTable("directory_connections")
          .set({ last_status: "needs_approval", last_error: `Paused deactivations: ${err.recent} in the last hour (limit ${err.threshold})` })
          .where("id", "=", conn.id)
          .where("last_status", "<>", "needs_approval")
          .returning("id")
          .executeTakeFirst();
        if (r) {
          await notifyRoles(tx, conn.org_id, ["owner", "admin"], {
            category: "directory.sync",
            severity: "critical",
            title: `${conn.name} is deactivating many people`,
            body: `${err.recent} people were deactivated through SCIM in the last hour. Nexus paused further deactivations until you approve them.`,
            entity: { type: "directory_connection", id: conn.id },
            link: "/directory-sync",
          });
        }
      });
      throw new ScimError(429, `Nexus paused deactivations from ${conn.name}: ${err.recent} in the last hour. An admin can approve more in Nexus → Directory sync.`);
    }
  };

  // Discovery.
  scim.get("/ServiceProviderConfig", (c) =>
    scimJson(c, {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: MAX_PAGE },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [{ type: "oauthbearertoken", name: "Bearer token", description: "The token shown when the SCIM connection was created in Nexus", primary: true }],
    }),
  );
  scim.get("/ResourceTypes", (c) =>
    scimJson(c, {
      schemas: [SCHEMA.list],
      totalResults: 2,
      Resources: [
        { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "User", name: "User", endpoint: "/Users", schema: SCHEMA.user, schemaExtensions: [{ schema: SCHEMA.enterprise, required: false }] },
        { schemas: ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], id: "Group", name: "Group", endpoint: "/Groups", schema: SCHEMA.group },
      ],
    }),
  );
  scim.get("/Schemas", (c) => scimJson(c, { schemas: [SCHEMA.list], totalResults: 3, Resources: [{ id: SCHEMA.user }, { id: SCHEMA.group }, { id: SCHEMA.enterprise }] }));

  // Users.
  scim.get("/Users", async (c) => {
    const deps = c.get("deps");
    const conn = c.get("conn");
    const filter = c.req.query("filter") ? parseFilter(c.req.query("filter")!) : null;
    const out = await deps.db.tenant(conn.org_id, async (tx) => {
      const eq = filter && simpleEq(filter, ["userName", "emails.value", "externalId", "id"]);
      let rows: LocalUser[];
      if (eq?.attr === "externalId") {
        rows = await visibleUsers(tx).innerJoin("directory_links", "directory_links.local_id", "users.id").where("directory_links.connection_id", "=", conn.id).where("directory_links.kind", "=", "user").where("directory_links.external_id", "=", eq.value).execute();
      } else if (eq?.attr === "id") {
        rows = /^[0-9a-f-]{36}$/i.test(eq.value) ? await visibleUsers(tx).where("users.id", "=", eq.value).execute() : [];
      } else if (eq) {
        rows = await visibleUsers(tx).where(sql`lower(users.email)`, "=", eq.value.toLowerCase()).execute();
      } else {
        rows = await visibleUsers(tx).orderBy("users.created_at").limit(20_000).execute();
      }
      const resources = await scimUsers(tx, deps, conn, rows);
      return filter && !eq ? resources.filter((r) => matches(filter, r)) : resources;
    });
    return scimJson(c, listResponse(out, page(c)));
  });

  scim.get("/Users/:id", async (c) => {
    const deps = c.get("deps");
    const conn = c.get("conn");
    const r = await deps.db.tenant(conn.org_id, async (tx) => {
      const u = await findUser(tx, c.req.param("id"));
      return u ? (await scimUsers(tx, deps, conn, [u]))[0] : null;
    });
    if (!r) throw new ScimError(404, "No such user");
    return scimJson(c, r);
  });

  const writeUser = async (c: C, id: string | null, toFields: (current: Record<string, any> | null) => UserFields) => {
    const deps = c.get("deps");
    const conn = c.get("conn");
    const res = await mutate(c, async (tx) => {
      const before = id ? await findUser(tx, id) : undefined;
      if (id && !before) throw new ScimError(404, "No such user");
      const current = before ? (await scimUsers(tx, deps, conn, [before]))[0]! : null;
      const done = await applyUser(tx, deps, c.get("meta"), conn, before, toFields(current));
      const after = (await findUser(tx, done.id)) ?? (await tx.selectFrom("users").select(userCols).where("users.id", "=", done.id).executeTakeFirstOrThrow());
      return { resource: (await scimUsers(tx, deps, conn, [after]))[0]!, invite: done.invite };
    });
    if (res.invite) await sendInvite(deps, res.invite).catch(() => undefined);
    return res.resource;
  };

  scim.post("/Users", async (c) => {
    const b = await body(c);
    const r = await writeUser(c, null, () => userFields(b));
    c.header("Location", r.meta.location);
    return scimJson(c, r, 201);
  });
  scim.put("/Users/:id", async (c) => {
    const b = await body(c);
    return scimJson(c, await writeUser(c, c.req.param("id"), () => userFields(b)));
  });
  scim.patch("/Users/:id", async (c) => {
    const ops = patchOps(await body(c));
    return scimJson(c, await writeUser(c, c.req.param("id"), (current) => userFields(patchUser(current!, ops))));
  });
  scim.delete("/Users/:id", async (c) => {
    const conn = c.get("conn");
    await mutate(c, async (tx) => {
      const u = await findUser(tx, c.req.param("id"));
      if (!u) throw new ScimError(404, "No such user");
      if (conn.deprovision === "none") {
        // Nexus leaves the person as they are; this source just stops managing them.
        await tx.deleteFrom("directory_links").where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "=", u.id).execute();
        return;
      }
      await checkDeactivationGuard(tx, conn);
      await offboard(tx, conn.org_id, u.id, { meta: c.get("meta"), actor: actorOf(conn).display, details: { connection_id: conn.id, via: "scim" } }, `Deleted in ${conn.name}`);
      await tx.deleteFrom("directory_links").where("connection_id", "=", conn.id).where("kind", "=", "user").where("local_id", "=", u.id).execute();
    });
    return c.body(null, 204);
  });

  // Groups.
  scim.get("/Groups", async (c) => {
    const deps = c.get("deps");
    const conn = c.get("conn");
    const filter = c.req.query("filter") ? parseFilter(c.req.query("filter")!) : null;
    const withMembers = !/\bmembers\b/i.test(c.req.query("excludedAttributes") ?? "");
    const out = await deps.db.tenant(conn.org_id, async (tx) => {
      const eq = filter && simpleEq(filter, ["displayName", "externalId", "id"]);
      let q = tx.selectFrom("groups").select(["groups.id", "groups.name", "groups.created_at", "groups.updated_at"]);
      if (eq?.attr === "displayName") q = q.where(sql`lower(groups.name)`, "=", eq.value.toLowerCase());
      if (eq?.attr === "id") q = q.where("groups.id", "=", /^[0-9a-f-]{36}$/i.test(eq.value) ? eq.value : "00000000-0000-0000-0000-000000000000");
      if (eq?.attr === "externalId") {
        q = q.innerJoin("directory_links", "directory_links.local_id", "groups.id").where("directory_links.connection_id", "=", conn.id).where("directory_links.kind", "=", "group").where("directory_links.external_id", "=", eq.value);
      }
      const rows = await q.orderBy("groups.created_at").limit(5000).execute();
      const needMembers = withMembers || (!!filter && !eq); // a members[…] filter needs them
      const resources = await Promise.all(rows.map((g) => scimGroup(tx, deps, conn, g, needMembers)));
      const hit = filter && !eq ? resources.filter((r) => matches(filter, r)) : resources;
      return withMembers ? hit : hit.map(({ members: _m, ...r }) => r);
    });
    return scimJson(c, listResponse(out, page(c)));
  });

  scim.get("/Groups/:id", async (c) => {
    const deps = c.get("deps");
    const conn = c.get("conn");
    const withMembers = !/\bmembers\b/i.test(c.req.query("excludedAttributes") ?? "");
    const r = await deps.db.tenant(conn.org_id, async (tx) => {
      const g = await findGroup(tx, c.req.param("id"));
      return g ? scimGroup(tx, deps, conn, g, withMembers) : null;
    });
    if (!r) throw new ScimError(404, "No such group");
    return scimJson(c, r);
  });

  scim.post("/Groups", async (c) => {
    const deps = c.get("deps");
    const conn = c.get("conn");
    const b = await body(c);
    const name = String(b.displayName ?? "").trim();
    const r = await mutate(c, async (tx) => {
      const clash = await tx.selectFrom("groups").select("id").where(sql`lower(name)`, "=", name.toLowerCase()).executeTakeFirst();
      if (clash) throw new ScimError(409, `A group named "${name}" already exists`, "uniqueness");
      if (!name) throw new ScimError(400, "displayName is required", "invalidValue");
      const id = newId();
      await tx.insertInto("groups").values({ id, org_id: conn.org_id, name: name.slice(0, 200), description: `Managed by ${conn.name} (SCIM)`, updated_at: new Date() }).execute();
      await link(tx, conn, "group", id, b.externalId ? String(b.externalId) : null);
      const members = await setMembers(tx, conn, id, { add: (Array.isArray(b.members) ? b.members : []).map((m: any) => String(m?.value ?? "")), remove: [] });
      await audit(tx, conn.org_id, { meta: c.get("meta") }, { type: "group.created", actor: actorOf(conn), target: { type: "group", id, display: name }, details: { connection_id: conn.id, via: "scim", members: members.added } });
      return scimGroup(tx, deps, conn, (await findGroup(tx, id))!, true);
    });
    c.header("Location", r.meta.location);
    return scimJson(c, r, 201);
  });

  const writeGroup = async (c: C, ch: ReturnType<typeof groupChanges>) => {
    const deps = c.get("deps");
    const conn = c.get("conn");
    return mutate(c, async (tx) => {
      const g = await findGroup(tx, c.req.param("id")!);
      if (!g) throw new ScimError(404, "No such group");
      await link(tx, conn, "group", g.id, ch.externalId || null);
      if (ch.displayName !== undefined && ch.displayName !== g.name) await renameGroup(tx, g.id, ch.displayName);
      const members = await setMembers(tx, conn, g.id, ch);
      if (members.added || members.removed || ch.displayName !== undefined) {
        await audit(tx, conn.org_id, { meta: c.get("meta") }, {
          type: "group.updated",
          actor: actorOf(conn),
          target: { type: "group", id: g.id, display: ch.displayName ?? g.name },
          details: { connection_id: conn.id, via: "scim", ...members, ...(ch.displayName !== undefined && ch.displayName !== g.name ? { renamed: { from: g.name, to: ch.displayName } } : {}) },
        });
      }
      return scimGroup(tx, deps, conn, (await findGroup(tx, g.id))!, !/\bmembers\b/i.test(c.req.query("excludedAttributes") ?? ""));
    });
  };

  scim.put("/Groups/:id", async (c) => {
    const b = await body(c);
    return scimJson(c, await writeGroup(c, { displayName: String(b.displayName ?? ""), externalId: b.externalId ? String(b.externalId) : undefined, add: [], remove: [], replace: (Array.isArray(b.members) ? b.members : []).map((m: any) => String(m?.value ?? "")) }));
  });
  scim.patch("/Groups/:id", async (c) => {
    const ch = groupChanges(patchOps(await body(c)));
    const r = await writeGroup(c, ch);
    return scimJson(c, r); // Okta and Entra both accept 200 with the resource
  });
  scim.delete("/Groups/:id", async (c) => {
    const conn = c.get("conn");
    await mutate(c, async (tx) => {
      const g = await findGroup(tx, c.req.param("id"));
      if (!g) throw new ScimError(404, "No such group");
      const members = await tx.selectFrom("group_members").select("user_id").where("group_id", "=", g.id).execute();
      await tx.deleteFrom("group_members").where("group_id", "=", g.id).execute();
      await tx.deleteFrom("app_assignments").where("principal_type", "=", "group").where("principal_id", "=", g.id).execute();
      await tx.deleteFrom("groups").where("id", "=", g.id).execute();
      await tx.deleteFrom("directory_links").where("connection_id", "=", conn.id).where("kind", "=", "group").where("local_id", "=", g.id).execute();
      await touchUsers(tx, conn.org_id, members.map((m) => m.user_id));
      await touchGroups(tx, conn.org_id, [g.id]);
      await audit(tx, conn.org_id, { meta: c.get("meta") }, { type: "group.deleted", actor: actorOf(conn), target: { type: "group", id: g.id, display: g.name }, details: { connection_id: conn.id, via: "scim", members: members.length } });
    });
    return c.body(null, 204);
  });

  scim.notFound(() => {
    throw new ScimError(404, "No such SCIM endpoint");
  });
  scim.onError((err, c) => {
    const e =
      err instanceof ScimError
        ? err
        : err instanceof ApiError
          ? new ScimError(err.status, err.message)
          : isUniqueViolation(err)
            ? new ScimError(409, "That conflicts with an existing resource", "uniqueness")
            : (console.error(`[scim ${c.get("meta")?.requestId}]`, err), new ScimError(500, "Something went wrong on our side"));
    if (e.status === 429) c.header("Retry-After", "300");
    return c.body(JSON.stringify(e.body()), e.status as 400, { "content-type": CONTENT_TYPE });
  });

  app.route("/scim/v2", scim as unknown as Hono<Env>);
}


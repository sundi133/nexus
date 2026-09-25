import { touchUsers } from "../provisioning/service.js";
import { scheduleDynamicEvaluation } from "./dynamic-groups-schedule.js";
import { suspendOwnedAgents } from "../ai-agents/lifecycle.js";
import { assertEmailAllowed } from "../org/domains.js";
import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Principal, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { loadUser, sessionOut } from "../auth/routes.js";
import { requirePermission } from "../auth/guard.js";
import { hashPassword, MIN_PASSWORD_LENGTH } from "../auth/passwords.js";
import { assertNotBreached } from "../auth/recovery.js";
import { notifyRoles } from "../notify/send.js";
import { issueInvitation, sendInvite, type PendingInvite } from "./invitations.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { badRequest, conflict, forbidden, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { decodeCursor, pageOf } from "../platform/pagination.js";
import { can, ROLES } from "../rbac.js";
import { bearer, body, Cursor, displayName, Group, Id, iso, json, page, patchOf, problemResponses, Role, Session, toUser, User, UserStatus } from "../schemas.js";

const UserDetail = User.extend({
  groups: z.array(Group.pick({ id: true, name: true })),
  sessions: z.array(Session),
}).openapi("UserDetail");

const UserInput = z.object({
  email: z.email(),
  given_name: z.string().trim().min(1).max(100),
  family_name: z.string().trim().max(100).default(""),
  title: z.string().trim().max(100).default(""),
  department: z.string().trim().max(100).default(""),
  password: z.string().min(MIN_PASSWORD_LENGTH).max(256).optional().openapi({
    description: "Optional initial password. Prefer `invite: true` so the user sets their own.",
  }),
  invite: z.boolean().default(false).openapi({
    description: "Create the user as `staged` and email them an invitation to set their password",
  }),
  roles: z.array(Role).default([]),
});

const UserPatch = patchOf(UserInput.pick({ given_name: true, family_name: true, title: true, department: true }))
  .extend({ manager_id: Id.nullable().optional().openapi({ description: "Their manager, or null for none" }) })
  .openapi("UserPatch");

const userQuery = (tx: Tx) =>
  tx
    .selectFrom("users")
    .selectAll("users")
    .select((eb) => [
      eb
        .selectFrom("user_roles")
        .whereRef("user_roles.user_id", "=", "users.id")
        .select(sql<string[]>`coalesce(array_agg(role ORDER BY role), '{}')`.as("r"))
        .as("roles"),
      eb
        .exists(
          eb
            .selectFrom("auth_factors")
            .whereRef("auth_factors.user_id", "=", "users.id")
            .where("auth_factors.verified_at", "is not", null),
        )
        .as("mfa_enrolled"),
      eb
        .selectFrom("directory_links")
        .innerJoin("directory_connections", "directory_connections.id", "directory_links.connection_id")
        .whereRef("directory_links.local_id", "=", "users.id")
        .where("directory_links.kind", "=", "user")
        .select("directory_connections.provider")
        .limit(1)
        .as("managed_by"),
    ]);

async function getUserOr404(tx: Tx, id: string) {
  const u = await loadUser(tx, id);
  if (!u) throw notFound("User");
  return u;
}

async function ownerCount(tx: Tx) {
  const r = await tx
    .selectFrom("user_roles")
    .innerJoin("users", "users.id", "user_roles.user_id")
    .where("role", "=", "owner")
    .where("users.status", "=", "active")
    .select((eb) => eb.fn.countAll<number>().as("n"))
    .executeTakeFirstOrThrow();
  return Number(r.n);
}

/** Revokes every live session for a user; returns how many were revoked. */
/** A manager must be someone else in the organization, and not someone who reports to this person. */
async function checkManager(tx: Tx, userId: string, managerId: string) {
  if (managerId === userId) throw badRequest("invalid_manager", "Someone can't be their own manager");
  let cur: string | null = managerId;
  for (let i = 0; cur && i < 50; i++) {
    const m: { id: string; manager_id: string | null } | undefined = await tx.selectFrom("users").select(["id", "manager_id"]).where("id", "=", cur).executeTakeFirst();
    if (!m) throw badRequest("invalid_manager", "That manager isn't in this organization");
    if (m.manager_id === userId) throw badRequest("invalid_manager", "That would make a reporting loop");
    cur = m.manager_id;
  }
}

export async function revokeUserSessions(tx: Tx, userId: string) {
  const r = await tx
    .updateTable("sessions")
    .set({ revoked_at: new Date() })
    .where("user_id", "=", userId)
    .where("revoked_at", "is", null)
    .executeTakeFirst();
  return Number(r.numUpdatedRows);
}

type Who = { principal: Principal; meta: RequestMeta };

export function registerUserRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/users",
      tags: ["Users"],
      summary: "List users",
      security: bearer,
      request: {
        query: Cursor.extend({
          q: z.string().trim().max(200).optional().openapi({ description: "Matches name or email" }),
          status: UserStatus.optional(),
          mfa: z.enum(["enrolled", "missing"]).optional(),
          role: z.enum(["any_admin", ...ROLES]).optional(),
        }),
      },
      responses: { 200: json(page(User, "UserPage")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      const q = c.req.valid("query");
      const after = decodeCursor(q.cursor);
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) => {
        let query = userQuery(tx).orderBy("users.id", "desc").limit(q.limit + 1);
        if (after) query = query.where("users.id", "<", after);
        if (q.status) query = query.where("users.status", "=", q.status);
        else query = query.where("users.status", "<>", "deprovisioned");
        if (q.q) {
          const like = `%${q.q.replace(/[%_\\]/g, "\\$&")}%`;
          query = query.where((eb) =>
            eb.or([
              eb("users.email", "ilike", like),
              eb(sql`users.given_name || ' ' || users.family_name`, "ilike", like),
            ]),
          );
        }
        const hasMfa = sql<boolean>`EXISTS (SELECT 1 FROM auth_factors f WHERE f.user_id = users.id AND f.verified_at IS NOT NULL)`;
        if (q.mfa === "enrolled") query = query.where(hasMfa);
        if (q.mfa === "missing") query = query.where(sql<boolean>`NOT ${hasMfa}`);
        if (q.role) {
          query = query.where((eb) =>
            eb.exists(
              eb
                .selectFrom("user_roles")
                .whereRef("user_roles.user_id", "=", "users.id")
                .$if(q.role !== "any_admin", (qb) => qb.where("user_roles.role", "=", q.role!)),
            ),
          );
        }
        return query.execute();
      });
      const pg = pageOf(rows, q.limit);
      return c.json({ data: pg.data.map(toUser), next_cursor: pg.next_cursor }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/users",
      tags: ["Users"],
      summary: "Create a user",
      security: bearer,
      request: body(UserInput),
      responses: { 201: json(User, "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:write");
      const input = c.req.valid("json");
      if (input.roles.length > 0 && !can(p.roles, "admins:manage")) {
        throw forbidden("Only owners can grant admin roles");
      }
      if (input.invite && input.password) throw badRequest("invalid_request", "Choose either an initial password or an invitation, not both");
      const meta = c.get("meta");
      const id = newId();
      if (input.password) await assertNotBreached(c.get("deps"), input.password);
      const passwordHash = input.password ? await hashPassword(input.password) : null;
      let invite: PendingInvite | null = null;
      try {
        const user = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          await assertEmailAllowed(tx, p.orgId, input.email);
          await tx
            .insertInto("users")
            .values({
              id,
              org_id: p.orgId,
              email: input.email.toLowerCase(),
              given_name: input.given_name,
              family_name: input.family_name,
              title: input.title,
              department: input.department,
              status: input.invite ? "staged" : "active",
              password_hash: passwordHash,
              attributes: JSON.stringify({}),
              updated_at: new Date(),
            })
            .execute();
          if (input.roles.length) {
            await tx.insertInto("user_roles").values(input.roles.map((role) => ({ org_id: p.orgId, user_id: id, role }))).execute();
          }
          await audit(tx, p.orgId, { principal: p, meta }, {
            type: "user.created",
            target: { type: "user", id, display: input.email },
            details: { roles: input.roles, invited: input.invite },
          });
          if (input.roles.length) await alertAdminGrant(tx, p.orgId, input.email, input.roles);
          await scheduleDynamicEvaluation(tx, p.orgId); // they may belong in dynamic groups
          if (input.invite) invite = await issueInvitation(tx, p, id);
          return getUserOr404(tx, id);
        });
        if (invite) await sendInvite(c.get("deps"), invite);
        return c.json(toUser(user), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("email_taken", "A user with this email already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/users/{id}",
      tags: ["Users"],
      summary: "Get a user with groups and active sessions",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(UserDetail), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const user = await getUserOr404(tx, id);
        const groups = await tx
          .selectFrom("group_members")
          .innerJoin("groups", "groups.id", "group_members.group_id")
          .select(["groups.id", "groups.name"])
          .where("group_members.user_id", "=", id)
          .orderBy("groups.name")
          .execute();
        const sessions = await tx
          .selectFrom("sessions")
          .selectAll()
          .where("user_id", "=", id)
          .where("revoked_at", "is", null)
          .where("expires_at", ">", new Date())
          .orderBy("last_seen_at", "desc")
          .execute();
        return { ...toUser(user), groups, sessions: sessions.map((s) => sessionOut(s, p.sessionId)) };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/users/{id}",
      tags: ["Users"],
      summary: "Update a user's profile",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(UserPatch) },
      responses: { 200: json(User), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "users:write");
      const { id } = c.req.valid("param");
      const patch = c.req.valid("json");
      const user = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const before = await getUserOr404(tx, id);
        if (patch.manager_id) await checkManager(tx, id, patch.manager_id);
        const changes = Object.fromEntries(
          Object.entries(patch).filter(([k, v]) => v !== undefined && before[k as keyof typeof before] !== v),
        );
        if (Object.keys(changes).length === 0) return before;
        await tx.updateTable("users").set({ ...changes, updated_at: new Date() }).where("id", "=", id).execute();
        await touchUsers(tx, p.orgId, [id]);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "user.updated",
          target: { type: "user", id, display: before.email },
          details: {
            changes: Object.fromEntries(
              Object.keys(changes).map((k) => [k, { from: before[k as keyof typeof before], to: changes[k] }]),
            ),
          },
        });
        return getUserOr404(tx, id);
      });
      return c.json(toUser(user), 200);
    },
  );

  // ---- Lifecycle actions (SPEC DIR-02, OPS-03) ---------------------------------

  const action = (
    name: string,
    summary: string,
    run: (tx: Tx, who: Who, user: Awaited<ReturnType<typeof getUserOr404>>) => Promise<Record<string, unknown>>,
  ) =>
    app.openapi(
      createRoute({
        method: "post",
        path: `/v1/users/{id}/${name}`,
        tags: ["Users"],
        summary,
        security: bearer,
        request: { params: z.object({ id: Id }), ...body(z.object({ reason: z.string().trim().max(500).default("") })) },
        responses: { 200: json(z.object({ user: User, effects: z.record(z.string(), z.unknown()) })), ...problemResponses },
      }),
      async (c) => {
        const p = requirePermission(c, "users:lifecycle");
        const { id } = c.req.valid("param");
        const { reason } = c.req.valid("json");
        const who = { principal: p, meta: c.get("meta") };
        const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          const user = await getUserOr404(tx, id);
          const effects = await run(tx, who, user);
          await touchUsers(tx, p.orgId, [id]); // status changes reach provisioned apps
          await audit(tx, p.orgId, who, {
            type: `user.${name.replace(/-/g, "_")}`,
            target: { type: "user", id, display: user.email },
            details: { reason, effects },
          });
          return { user: toUser(await getUserOr404(tx, id)), effects };
        });
        return c.json(out, 200);
      },
    );

  const assertNotSelfOrLastOwner = async (tx: Tx, who: Who, user: { id: string; roles: string[] | null }) => {
    if (user.id === who.principal.userId) throw badRequest("cannot_target_self", "You can't do this to your own account");
    if (user.roles?.includes("owner") && !can(who.principal.roles, "admins:manage")) {
      throw forbidden("Only owners can suspend another owner");
    }
    if (user.roles?.includes("owner") && (await ownerCount(tx)) <= 1) {
      throw conflict("last_owner", "The organization must keep at least one active owner");
    }
  };

  action("suspend", "Suspend a user: blocks sign-in and revokes all sessions", async (tx, who, user) => {
    if (user.status === "suspended") throw conflict("already_suspended", "User is already suspended");
    await assertNotSelfOrLastOwner(tx, who, user);
    await tx.updateTable("users").set({ status: "suspended", updated_at: new Date() }).where("id", "=", user.id).execute();
    return { sessions_revoked: await revokeUserSessions(tx, user.id) };
  });

  action("activate", "Reactivate a suspended or staged user", async (tx, _who, user) => {
    if (user.status === "active") throw conflict("already_active", "User is already active");
    if (user.status === "deprovisioned") throw conflict("deprovisioned", "Deprovisioned users can't be reactivated");
    await tx.updateTable("users").set({ status: "active", updated_at: new Date() }).where("id", "=", user.id).execute();
    return {};
  });

  action("revoke-sessions", "Sign a user out everywhere (web, mobile, CLI)", async (tx, _who, user) => ({
    sessions_revoked: await revokeUserSessions(tx, user.id),
  }));

  action("reset-mfa", "Remove all of a user's MFA factors so they can re-enroll", async (tx, who, user) => {
    if (user.id === who.principal.userId) throw badRequest("cannot_target_self", "Manage your own factors in Settings → Security");
    const del = await tx.deleteFrom("auth_factors").where("user_id", "=", user.id).executeTakeFirst();
    return { factors_removed: Number(del.numDeletedRows), sessions_revoked: await revokeUserSessions(tx, user.id) };
  });

  action("contain", "Contain a possibly compromised user: suspend and revoke everything, in one step", async (tx, who, user) => {
    await assertNotSelfOrLastOwner(tx, who, user);
    await tx.updateTable("users").set({ status: "suspended", updated_at: new Date() }).where("id", "=", user.id).execute();
    const effects = {
      suspended: true,
      sessions_revoked: await revokeUserSessions(tx, user.id),
      agents_suspended: await suspendOwnedAgents(tx, who.principal.orgId, user.id, `Owner ${user.email} was contained`, who),
    };
    await notifyRoles(tx, who.principal.orgId, ["owner", "admin", "security_analyst"], {
      category: "security.alert",
      severity: "critical",
      title: `${displayName(user)} was contained`,
      body: `Account suspended, ${effects.sessions_revoked} session(s) revoked, and accounts in provisioned apps are being deactivated.`,
      entity: { type: "user", id: user.id },
      link: `/users/${user.id}`,
    });
    return effects;
  });

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/users/{id}/roles",
      tags: ["Users"],
      summary: "Set a user's admin roles",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ roles: z.array(Role) })) },
      responses: { 200: json(User), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "admins:manage");
      const { id } = c.req.valid("param");
      const roles = [...new Set(c.req.valid("json").roles)];
      const user = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const before = await getUserOr404(tx, id);
        const prev = before.roles ?? [];
        if (prev.includes("owner") && !roles.includes("owner") && (await ownerCount(tx)) <= 1) {
          throw conflict("last_owner", "The organization must keep at least one active owner");
        }
        await tx.deleteFrom("user_roles").where("user_id", "=", id).execute();
        if (roles.length) await tx.insertInto("user_roles").values(roles.map((role) => ({ org_id: p.orgId, user_id: id, role }))).execute();
        const added = roles.filter((r) => !prev.includes(r));
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "user.roles_changed",
          target: { type: "user", id, display: before.email },
          details: { from: prev, to: roles },
        });
        if (added.length) await alertAdminGrant(tx, p.orgId, before.email, added);
        return getUserOr404(tx, id);
      });
      return c.json(toUser(user), 200);
    },
  );
}

/** Granting admin rights is a classic persistence move, so owners always hear about it. */
async function alertAdminGrant(tx: Tx, orgId: string, email: string, roles: string[]) {
  await notifyRoles(tx, orgId, ["owner"], {
    category: "security.admin_change",
    severity: "warning",
    title: `Admin role granted to ${email}`,
    body: `Roles added: ${roles.join(", ")}`,
    link: "/users?role=any_admin",
  });
}


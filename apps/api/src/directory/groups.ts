import { touchGroups, touchUsers } from "../provisioning/service.js";
import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { decodeCursor, pageOf } from "../platform/pagination.js";
import { bearer, body, Cursor, displayName, Group, GroupRule, Id, iso, json, page, patchOf, problemResponses, toUser, User } from "../schemas.js";
import { sql } from "kysely";
import { evaluateDynamicGroups, matchingUsers } from "./dynamic-groups.js";

const GroupInput = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().trim().max(500).default(""),
  rule: z.union([GroupRule, z.null()]).default(null).openapi({ description: "Makes this a dynamic group. null: members are managed by hand" }),
});

const groupQuery = (tx: Tx) =>
  tx
    .selectFrom("groups")
    .selectAll("groups")
    .select((eb) => [
      eb
        .selectFrom("group_members")
        .whereRef("group_members.group_id", "=", "groups.id")
        .select((e) => e.fn.countAll<number>().as("n"))
        .as("member_count"),
      eb
        .selectFrom("directory_links")
        .innerJoin("directory_connections", "directory_connections.id", "directory_links.connection_id")
        .whereRef("directory_links.local_id", "=", "groups.id")
        .where("directory_links.kind", "=", "group")
        .select("directory_connections.name")
        .limit(1)
        .as("managed_by"),
    ]);

type GroupRow = Awaited<ReturnType<ReturnType<typeof groupQuery>["executeTakeFirstOrThrow"]>>;

const toGroup = (g: GroupRow) => ({
  id: g.id,
  name: g.name,
  description: g.description,
  member_count: Number(g.member_count ?? 0),
  rule: (g.rule as z.infer<typeof GroupRule> | null) ?? null,
  rule_evaluated_at: g.rule_evaluated_at ? iso(g.rule_evaluated_at) : null,
  managed_by: g.managed_by ?? null,
  created_at: iso(g.created_at),
  updated_at: iso(g.updated_at),
});

async function getGroup(tx: Tx, id: string) {
  const g = await groupQuery(tx).where("groups.id", "=", id).executeTakeFirst();
  if (!g) throw notFound("Group");
  return g;
}

/** Members of a dynamic group follow its rule; members of a directory's group follow the directory. */
function assertManualMembers(g: GroupRow) {
  if (g.rule) throw conflict("dynamic_group", "This group's members follow its rule. Change the rule instead.");
  if (g.managed_by) throw conflict("directory_managed", `This group's members come from ${g.managed_by}. Change them there.`);
}

/** A rule can't be combined with a directory's membership or with requested access to the group. */
async function assertCanHaveRule(tx: Tx, g: GroupRow) {
  if (g.managed_by) throw conflict("directory_managed", `This group's members come from ${g.managed_by}, so it can't have a rule.`);
  const cat = await tx.selectFrom("access_catalog").select("id").where("resource_type", "=", "group").where("resource_id", "=", g.id).executeTakeFirst();
  if (cat) throw conflict("requestable", "People can request this group in the access catalog. Remove it from the catalog before giving it a rule.");
}

const RulePreview = z
  .object({
    count: z.number().int(),
    sample: z.array(z.object({ id: Id, email: z.string(), name: z.string(), department: z.string(), title: z.string() })),
    adds: z.number().int().optional().openapi({ description: "With group_id: people the rule would add" }),
    removes: z.number().int().optional().openapi({ description: "With group_id: members the rule would remove" }),
  })
  .openapi("GroupRulePreview");

export function registerGroupRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/groups/rule-preview",
      tags: ["Groups"],
      summary: "Preview who a rule matches",
      description: "Counts the people a dynamic group rule matches now. With group_id, also how many it would add to and remove from that group.",
      security: bearer,
      request: body(z.object({ rule: GroupRule, group_id: Id.optional() })),
      responses: { 200: json(RulePreview), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:read");
      const { rule, group_id } = c.req.valid("json");
      const r = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const all = await matchingUsers(tx, rule);
        let diff: { adds?: number; removes?: number } = {};
        if (group_id) {
          await getGroup(tx, group_id);
          const have = new Set((await tx.selectFrom("group_members").select("user_id").where("group_id", "=", group_id).execute()).map((m) => m.user_id));
          const want = new Set(all.map((u) => u.id));
          diff = { adds: [...want].filter((x) => !have.has(x)).length, removes: [...have].filter((x) => !want.has(x)).length };
        }
        return { count: all.length, sample: all.slice(0, 10).map((u) => ({ id: u.id, email: u.email, name: displayName(u), department: u.department, title: u.title })), ...diff };
      });
      return c.json(r, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/groups",
      tags: ["Groups"],
      summary: "List groups",
      security: bearer,
      request: { query: Cursor.extend({ q: z.string().trim().max(200).optional() }) },
      responses: { 200: json(page(Group, "GroupPage")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:read");
      const q = c.req.valid("query");
      const after = decodeCursor(q.cursor);
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) => {
        let query = groupQuery(tx).orderBy("groups.id", "desc").limit(q.limit + 1);
        if (after) query = query.where("groups.id", "<", after);
        if (q.q) query = query.where("groups.name", "ilike", `%${q.q.replace(/[%_\\]/g, "\\$&")}%`);
        return query.execute();
      });
      const pg = pageOf(rows, q.limit);
      return c.json({ data: pg.data.map(toGroup), next_cursor: pg.next_cursor }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/groups",
      tags: ["Groups"],
      summary: "Create a group",
      security: bearer,
      request: body(GroupInput),
      responses: { 201: json(Group, "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:write");
      const input = c.req.valid("json");
      const id = newId();
      try {
        const g = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          await tx.insertInto("groups").values({ id, org_id: p.orgId, ...input, rule: input.rule ? JSON.stringify(input.rule) : null, updated_at: new Date() }).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "group.created", target: { type: "group", id, display: input.name }, details: input.rule ? { rule: input.rule } : undefined });
          if (input.rule) await evaluateDynamicGroups(tx, p.orgId, c.get("meta"), id);
          return getGroup(tx, id);
        });
        return c.json(toGroup(g), 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "A group with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/groups/{id}",
      tags: ["Groups"],
      summary: "Get a group",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(Group), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:read");
      const g = await c.get("deps").db.tenant(p.orgId, (tx) => getGroup(tx, c.req.valid("param").id));
      return c.json(toGroup(g), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/groups/{id}",
      tags: ["Groups"],
      summary: "Update a group",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(patchOf(GroupInput)) },
      responses: { 200: json(Group), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:write");
      const { id } = c.req.valid("param");
      const patch = c.req.valid("json");
      try {
        const g = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          const before = await getGroup(tx, id);
          if (patch.rule) await assertCanHaveRule(tx, before);
          const { rule, ...rest } = patch;
          await tx
            .updateTable("groups")
            .set({ ...rest, ...(rule !== undefined ? { rule: rule ? JSON.stringify(rule) : null } : {}), updated_at: new Date() })
            .where("id", "=", id)
            .execute();
          if (patch.name && patch.name !== before.name) await touchGroups(tx, p.orgId, [id]);
          // Turning the rule off keeps today's members, now managed by hand.
          if (rule) await evaluateDynamicGroups(tx, p.orgId, c.get("meta"), id);
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "group.updated",
            target: { type: "group", id, display: before.name },
            details: { changes: patch },
          });
          return getGroup(tx, id);
        });
        return c.json(toGroup(g), 200);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "A group with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/groups/{id}",
      tags: ["Groups"],
      summary: "Delete a group",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 204: { description: "Deleted" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:write");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const g = await getGroup(tx, id);
        const members = await tx.selectFrom("group_members").select("user_id").where("group_id", "=", id).execute();
        await tx.deleteFrom("groups").where("id", "=", id).execute();
        await tx.deleteFrom("app_assignments").where("principal_type", "=", "group").where("principal_id", "=", id).execute();
        // Its members may lose app access; pushed copies of the group are removed from apps.
        await touchUsers(tx, p.orgId, members.map((m) => m.user_id));
        await touchGroups(tx, p.orgId, [id]);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "group.deleted",
          target: { type: "group", id, display: g.name },
          details: { member_count: Number(g.member_count ?? 0) },
        });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/groups/{id}/members",
      tags: ["Groups"],
      summary: "List group members",
      security: bearer,
      request: { params: z.object({ id: Id }), query: Cursor },
      responses: { 200: json(page(User, "GroupMemberPage")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:read");
      const { id } = c.req.valid("param");
      const q = c.req.valid("query");
      const after = decodeCursor(q.cursor);
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await getGroup(tx, id);
        let query = tx
          .selectFrom("users")
          .innerJoin("group_members", "group_members.user_id", "users.id")
          .selectAll("users")
          .select((eb) => [
            eb
              .selectFrom("user_roles")
              .whereRef("user_roles.user_id", "=", "users.id")
              .select(sql<string[]>`coalesce(array_agg(role ORDER BY role), '{}')`.as("r"))
              .as("roles"),
            eb
              .exists(eb.selectFrom("auth_factors").whereRef("auth_factors.user_id", "=", "users.id").where("auth_factors.verified_at", "is not", null))
              .as("mfa_enrolled"),
          ])
          .where("group_members.group_id", "=", id)
          .orderBy("users.id", "desc")
          .limit(q.limit + 1);
        if (after) query = query.where("users.id", "<", after);
        return query.execute();
      });
      const pg = pageOf(rows, q.limit);
      return c.json({ data: pg.data.map(toUser), next_cursor: pg.next_cursor }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/groups/{id}/members",
      tags: ["Groups"],
      summary: "Add users to a group",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ user_ids: z.array(Id).min(1).max(500) })) },
      responses: { 200: json(Group), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:write");
      const { id } = c.req.valid("param");
      const { user_ids } = c.req.valid("json");
      const g = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const group = await getGroup(tx, id);
        assertManualMembers(group);
        const found = await tx.selectFrom("users").select("id").where("id", "in", user_ids).execute();
        if (found.length !== new Set(user_ids).size) throw notFound("One or more users");
        const added = await tx
          .insertInto("group_members")
          .values(found.map((u) => ({ org_id: p.orgId, group_id: id, user_id: u.id })))
          .onConflict((oc) => oc.doNothing())
          .returning("user_id")
          .execute();
        if (added.length) {
          await touchUsers(tx, p.orgId, added.map((a) => a.user_id));
          await touchGroups(tx, p.orgId, [id]);
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "group.members_added",
            target: { type: "group", id, display: group.name },
            details: { user_ids: added.map((a) => a.user_id) },
          });
        }
        return getGroup(tx, id);
      });
      return c.json(toGroup(g), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/groups/{id}/members/{userId}",
      tags: ["Groups"],
      summary: "Remove a user from a group",
      security: bearer,
      request: { params: z.object({ id: Id, userId: Id }) },
      responses: { 204: { description: "Removed" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "groups:write");
      const { id, userId } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const group = await getGroup(tx, id);
        assertManualMembers(group);
        const r = await tx.deleteFrom("group_members").where("group_id", "=", id).where("user_id", "=", userId).executeTakeFirst();
        if (Number(r.numDeletedRows) === 0) throw notFound("Membership");
        await touchUsers(tx, p.orgId, [userId]);
        await touchGroups(tx, p.orgId, [id]);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "group.members_removed",
          target: { type: "group", id, display: group.name },
          details: { user_ids: [userId] },
        });
      });
      return c.body(null, 204);
    },
  );
}

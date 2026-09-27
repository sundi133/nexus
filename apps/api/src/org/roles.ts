import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { notifyRoles } from "../notify/send.js";
import { NOT_IN_CUSTOM_ROLES, PERMISSIONS, rolePermissions, ROLES, SCOPABLE, SCOPABLE_ROLES, SCOPED_EXTRAS, type Permission } from "../rbac.js";
import { bearer, body, Id, iso, json, problemResponses, Timestamp } from "../schemas.js";

/**
 * RBAC v2 (SPEC RBAC-02, RBAC-03): custom roles from the permission catalog,
 * and grants that give someone a custom role, or a built-in role limited to
 * some groups. Only owners (admins:manage) change who is an admin.
 */

const PermissionEnum = z.enum(PERMISSIONS);

const CustomRole = z
  .object({ id: Id, name: z.string(), description: z.string(), permissions: z.array(PermissionEnum), holders: z.number().int(), created_at: Timestamp, updated_at: Timestamp })
  .openapi("CustomRole");

const Catalog = z
  .object({
    builtin: z.array(z.object({ key: z.enum(ROLES), permissions: z.array(PermissionEnum), scopable: z.boolean() })),
    custom: z.array(CustomRole),
    permissions: z.array(z.object({ key: PermissionEnum, scopable: z.boolean().openapi({ description: "Can be limited to groups in a scoped grant" }), in_custom_roles: z.boolean() })),
  })
  .openapi("RoleCatalog");

const RoleInput = z.object({
  name: z.string().trim().min(1).max(60),
  description: z.string().trim().max(300).default(""),
  permissions: z.array(PermissionEnum).min(1),
});

const Grant = z
  .object({
    id: Id,
    role: z.string().openapi({ description: "A built-in role (helpdesk, security_analyst, readonly) or custom:<id>" }),
    name: z.string(),
    scope: z.array(z.object({ id: Id, name: z.string() })).openapi({ description: "Empty: the whole organization" }),
    created_at: Timestamp,
  })
  .openapi("RoleGrant");

const GrantInput = z.object({
  grants: z
    .array(
      z.object({
        role: z.string().regex(/^(helpdesk|security_analyst|readonly|custom:[0-9a-f-]{36})$/, "A scopable built-in role or custom:<id>"),
        scope_group_ids: z.array(Id).max(50).default([]),
      }),
    )
    .max(20),
});

async function catalog(tx: Tx): Promise<z.infer<typeof Catalog>> {
  const custom = await tx
    .selectFrom("custom_roles")
    .selectAll("custom_roles")
    .select((eb) => eb.selectFrom("role_grants").whereRef("role_grants.custom_role_id", "=", "custom_roles.id").select((e) => e.fn.countAll<number>().as("n")).as("holders"))
    .orderBy("name")
    .execute();
  return {
    builtin: ROLES.map((r) => ({ key: r, permissions: rolePermissions(r), scopable: (SCOPABLE_ROLES as readonly string[]).includes(r) })),
    custom: custom.map((r) => ({ id: r.id, name: r.name, description: r.description, permissions: r.permissions as Permission[], holders: Number(r.holders ?? 0), created_at: iso(r.created_at), updated_at: iso(r.updated_at) })),
    permissions: PERMISSIONS.map((p) => ({ key: p, scopable: SCOPABLE.includes(p) || SCOPED_EXTRAS.includes(p), in_custom_roles: !NOT_IN_CUSTOM_ROLES.includes(p) })),
  };
}

async function grantsOf(tx: Tx, userId: string): Promise<z.infer<typeof Grant>[]> {
  const rows = await tx
    .selectFrom("role_grants")
    .leftJoin("custom_roles", "custom_roles.id", "role_grants.custom_role_id")
    .select(["role_grants.id", "role_grants.builtin_role", "role_grants.custom_role_id", "role_grants.scope_group_ids", "role_grants.created_at", "custom_roles.name"])
    .where("role_grants.user_id", "=", userId)
    .orderBy("role_grants.created_at")
    .execute();
  const ids = [...new Set(rows.flatMap((r) => r.scope_group_ids))];
  const names = new Map(ids.length ? (await tx.selectFrom("groups").select(["id", "name"]).where("id", "in", ids).execute()).map((g) => [g.id, g.name]) : []);
  return rows.map((r) => ({
    id: r.id,
    role: r.builtin_role ?? `custom:${r.custom_role_id}`,
    name: r.name ?? r.builtin_role!.replace("_", " "),
    scope: r.scope_group_ids.map((id) => ({ id, name: names.get(id) ?? "(deleted group)" })),
    created_at: iso(r.created_at),
  }));
}

export function registerRoleRoutes(app: App) {
  const stepUp = async (c: Parameters<typeof requireRecentMfa>[0], tx: Tx, p: Parameters<typeof requireRecentMfa>[1]) => requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);

  app.openapi(
    createRoute({ method: "get", path: "/v1/roles", tags: ["Roles"], summary: "Built-in roles, custom roles and the permission catalog", security: bearer, responses: { 200: json(Catalog), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "users:read", { scoped: true });
      return c.json(await c.get("deps").db.tenant(p.orgId, catalog), 200);
    },
  );

  const checkPermissions = (perms: Permission[]) => {
    const bad = perms.filter((x) => NOT_IN_CUSTOM_ROLES.includes(x));
    if (bad.length) throw badRequest("not_allowed", `Custom roles can't include ${bad.join(", ")}: managing admins stays with owners`);
  };

  app.openapi(
    createRoute({ method: "post", path: "/v1/roles", tags: ["Roles"], summary: "Create a custom role", security: bearer, request: body(RoleInput), responses: { 201: json(Catalog, "Created"), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "admins:manage");
      const input = c.req.valid("json");
      checkPermissions(input.permissions);
      try {
        const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          await stepUp(c, tx, p);
          const id = newId();
          await tx.insertInto("custom_roles").values({ id, org_id: p.orgId, name: input.name, description: input.description, permissions: [...new Set(input.permissions)], created_by: p.apiKey ? null : p.userId }).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "role.created", target: { type: "role", id, display: input.name }, details: { permissions: input.permissions } });
          return catalog(tx);
        });
        return c.json(out, 201);
      } catch (e) {
        if (isUniqueViolation(e)) throw conflict("name_taken", "A role with this name already exists");
        throw e;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/roles/{id}",
      tags: ["Roles"],
      summary: "Change a custom role",
      description: "Takes effect for everyone who has it at their next request.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(RoleInput.partial()) },
      responses: { 200: json(Catalog), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "admins:manage");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      if (input.permissions) checkPermissions(input.permissions);
      try {
        const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          const before = await tx.selectFrom("custom_roles").selectAll().where("id", "=", id).executeTakeFirst();
          if (!before) throw notFound("Role");
          await stepUp(c, tx, p);
          await tx
            .updateTable("custom_roles")
            .set({ ...(input.name ? { name: input.name } : {}), ...(input.description !== undefined ? { description: input.description } : {}), ...(input.permissions ? { permissions: [...new Set(input.permissions)] } : {}), updated_at: new Date() })
            .where("id", "=", id)
            .execute();
          const added = (input.permissions ?? []).filter((x) => !before.permissions.includes(x));
          const removed = input.permissions ? before.permissions.filter((x) => !input.permissions!.includes(x as Permission)) : [];
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "role.updated", target: { type: "role", id, display: before.name }, details: { added, removed, ...(input.name ? { name: input.name } : {}) } });
          if (added.length) {
            await notifyRoles(tx, p.orgId, ["owner"], { category: "security.alert", severity: "warning", title: `Role "${before.name}" gained ${added.join(", ")}`, body: `Changed by ${p.email}. Everyone with the role has it now.`, link: "/settings/roles" });
          }
          return catalog(tx);
        });
        return c.json(out, 200);
      } catch (e) {
        if (isUniqueViolation(e)) throw conflict("name_taken", "A role with this name already exists");
        throw e;
      }
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/roles/{id}", tags: ["Roles"], summary: "Delete a custom role", description: "Everyone who had it loses it.", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(Catalog), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "admins:manage");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const before = await tx.selectFrom("custom_roles").selectAll().where("id", "=", id).executeTakeFirst();
        if (!before) throw notFound("Role");
        await stepUp(c, tx, p);
        const holders = await tx.selectFrom("role_grants").select("user_id").where("custom_role_id", "=", id).execute();
        await tx.deleteFrom("custom_roles").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "role.deleted", target: { type: "role", id, display: before.name }, details: { holders: holders.map((h) => h.user_id) } });
        return catalog(tx);
      });
      return c.json(out, 200);
    },
  );

  // ---- A person's grants ----

  app.openapi(
    createRoute({ method: "get", path: "/v1/users/{id}/role-grants", tags: ["Roles"], summary: "A person's custom and scoped roles", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(z.object({ data: z.array(Grant) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      const { id } = c.req.valid("param");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => grantsOf(tx, id)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/users/{id}/role-grants",
      tags: ["Roles"],
      summary: "Set a person's custom and scoped roles",
      description:
        "Replaces them. A built-in role (Help Desk, Security Analyst, Read-only) needs groups here (for the whole organization, use the user's roles instead); a custom role applies to the whole organization unless groups are given. Within groups, only permissions about people and their devices are limited; other permissions in the role don't apply, except reading groups and apps.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(GrantInput) },
      responses: { 200: json(z.object({ data: z.array(Grant) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "admins:manage");
      const { id } = c.req.valid("param");
      const { grants } = c.req.valid("json");
      const roleKeys = grants.map((g) => g.role);
      if (new Set(roleKeys).size !== roleKeys.length) throw badRequest("duplicate_role", "Each role can be granted once; list all its groups together");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const user = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", id).executeTakeFirst();
        if (!user) throw notFound("User");
        if (user.status === "deprovisioned" && grants.length) throw conflict("deprovisioned", "This person is offboarded");
        await stepUp(c, tx, p);
        const customIds = grants.filter((g) => g.role.startsWith("custom:")).map((g) => g.role.slice(7));
        const custom = new Map(customIds.length ? (await tx.selectFrom("custom_roles").select(["id", "name"]).where("id", "in", customIds).execute()).map((r) => [r.id, r.name]) : []);
        const groupIds = [...new Set(grants.flatMap((g) => g.scope_group_ids))];
        const found = groupIds.length ? (await tx.selectFrom("groups").select("id").where("id", "in", groupIds).execute()).length : 0;
        if (found !== groupIds.length) throw notFound("One or more groups");
        for (const g of grants) {
          if (g.role.startsWith("custom:") && !custom.has(g.role.slice(7))) throw notFound("Role");
          if (!g.role.startsWith("custom:") && !g.scope_group_ids.length) throw badRequest("scope_required", `A built-in role granted here needs groups; for the whole organization, add ${g.role} to the user's roles`);
        }
        const before = await grantsOf(tx, id);
        await tx.deleteFrom("role_grants").where("user_id", "=", id).execute();
        if (grants.length) {
          await tx
            .insertInto("role_grants")
            .values(
              grants.map((g) => ({
                id: newId(),
                org_id: p.orgId,
                user_id: id,
                builtin_role: g.role.startsWith("custom:") ? null : (g.role as "helpdesk" | "security_analyst" | "readonly"),
                custom_role_id: g.role.startsWith("custom:") ? g.role.slice(7) : null,
                scope_group_ids: [...new Set(g.scope_group_ids)],
                created_by: p.apiKey ? null : p.userId,
              })),
            )
            .execute();
        }
        const after = await grantsOf(tx, id);
        const label = (xs: z.infer<typeof Grant>[]) => xs.map((g) => `${g.name}${g.scope.length ? ` (${g.scope.map((s) => s.name).join(", ")})` : ""}`);
        // Same event as role changes, so the "Admin roles changed" alert covers it.
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "user.roles_changed", target: { type: "user", id, display: user.email }, details: { grants: { from: label(before), to: label(after) } } });
        const gained = label(after).filter((x) => !label(before).includes(x));
        if (gained.length) {
          await notifyRoles(tx, p.orgId, ["owner", "admin"], { category: "security.alert", severity: "warning", title: `${user.email} was given ${gained.join(", ")}`, body: `By ${p.email}.`, entity: { type: "user", id }, link: `/users/${id}` });
        }
        return after;
      });
      return c.json({ data: out }, 200);
    },
  );
}

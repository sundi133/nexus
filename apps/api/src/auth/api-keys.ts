import { createRoute, z } from "@hono/zod-openapi";
import { randomBytes } from "node:crypto";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { isUniqueViolation, type Tx } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { GRANTABLE_TO_KEYS, permissionsFor, type Permission } from "../rbac.js";
import { bearer, body, Id, iso, json, Permission as PermissionSchema, problemResponses } from "../schemas.js";
import { requirePermission, requireRecentMfa } from "./guard.js";
import { verifiedFactorTypes } from "./routes.js";
import { hashToken } from "./tokens.js";

/** Scoped, expiring API keys for automation (SPEC INT-02). The key is shown once. */

const ApiKey = z
  .object({
    id: Id,
    name: z.string(),
    prefix: z.string().openapi({ description: "The start of the key, to recognize it" }),
    scopes: z.array(PermissionSchema),
    created_by: z.string().nullable(),
    created_at: z.string(),
    expires_at: z.string(),
    last_used_at: z.string().nullable(),
    last_used_ip: z.string(),
    status: z.enum(["active", "expired", "revoked"]),
  })
  .openapi("ApiKey");

async function list(tx: Tx) {
  const rows = await tx
    .selectFrom("api_keys")
    .leftJoin("users", "users.id", "api_keys.created_by")
    .selectAll("api_keys")
    .select("users.email as creator")
    .orderBy("api_keys.created_at", "desc")
    .execute();
  return rows.map((k) => ({
    id: k.id,
    name: k.name,
    prefix: k.prefix,
    scopes: k.scopes as Permission[],
    created_by: k.creator ?? null,
    created_at: iso(k.created_at),
    expires_at: iso(k.expires_at),
    last_used_at: k.last_used_at ? iso(k.last_used_at) : null,
    last_used_ip: k.last_used_ip,
    status: k.revoked_at ? ("revoked" as const) : k.expires_at.getTime() <= Date.now() ? ("expired" as const) : ("active" as const),
  }));
}

export function registerApiKeyRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/api-keys",
      tags: ["API keys"],
      summary: "API keys (never the keys themselves)",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(ApiKey), grantable_scopes: z.array(PermissionSchema) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "api_keys:manage");
      const mine = new Set(permissionsFor(p.roles));
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, list), grantable_scopes: GRANTABLE_TO_KEYS.filter((s) => mine.has(s)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/api-keys",
      tags: ["API keys"],
      summary: "Create an API key (requires recent MFA)",
      description: "Scopes must be ones you hold yourself, and can't include managing admins or keys. The key is returned once.",
      security: bearer,
      request: body(
        z.object({
          name: z.string().trim().min(1).max(100),
          scopes: z.array(PermissionSchema).min(1),
          expires_in_days: z.number().int().min(1).max(365).default(90),
        }),
      ),
      responses: { 201: json(z.object({ key: z.string().openapi({ description: "Shown once. Send as `Authorization: Bearer <key>`." }), api_key: ApiKey }), "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "api_keys:manage");
      if (p.apiKey) throw badRequest("keys_cannot_create_keys", "API keys can't create API keys");
      const input = c.req.valid("json");
      const mine = new Set(permissionsFor(p.roles));
      const bad = input.scopes.filter((s) => !GRANTABLE_TO_KEYS.includes(s) || !mine.has(s));
      if (bad.length) throw badRequest("scope_not_allowed", `These scopes can't be granted: ${bad.join(", ")}`);
      const key = `nxk_${randomBytes(32).toString("base64url")}`;
      const id = newId();
      try {
        const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
          requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
          if (await tx.selectFrom("api_keys").select("id").where("name", "=", input.name).where("revoked_at", "is", null).executeTakeFirst()) {
            throw conflict("name_taken", "An active key with this name already exists");
          }
          await tx
            .insertInto("api_keys")
            .values({
              id,
              org_id: p.orgId,
              name: input.name,
              prefix: key.slice(0, 12),
              key_hash: hashToken(key),
              scopes: [...new Set(input.scopes)].sort(),
              created_by: p.userId,
              expires_at: new Date(Date.now() + input.expires_in_days * 86400_000),
            })
            .execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "api_key.created",
            target: { type: "api_key", id, display: input.name },
            details: { scopes: input.scopes, expires_in_days: input.expires_in_days },
          });
          return (await list(tx)).find((k) => k.id === id)!;
        });
        return c.json({ key, api_key: out }, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("try_again", "Please try again");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/api-keys/{id}", tags: ["API keys"], summary: "Revoke an API key (takes effect immediately)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Revoked" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "api_keys:manage");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.updateTable("api_keys").set({ revoked_at: new Date() }).where("id", "=", id).where("revoked_at", "is", null).returning("name").executeTakeFirst();
        if (!r) throw notFound("Active API key");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "api_key.revoked", target: { type: "api_key", id, display: r.name } });
      });
      return c.body(null, 204);
    },
  );
}

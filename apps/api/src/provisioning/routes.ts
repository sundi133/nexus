import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { sql } from "kysely";
import type { App, Env, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, notFound } from "../platform/errors.js";
import { assertSafeUrl, UnsafeUrlError } from "../platform/outbound.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { ScimClient, ScimError } from "./scim-client.js";
import { tokenAad, touchApp, touchUsers } from "./service.js";

const Account = z.object({
  user_id: Id,
  email: z.string(),
  display_name: z.string(),
  state: z.enum(["active", "inactive", "error", "pending"]),
  remote_id: z.string().nullable(),
  last_synced_at: z.string().nullable(),
  last_error: z.string(),
});
const Provisioning = z
  .object({
    configured: z.boolean(),
    enabled: z.boolean(),
    base_url: z.string(),
    push_groups: z.boolean(),
    on_unassign: z.enum(["deactivate", "delete"]),
    last_error: z.string(),
    last_error_at: z.string().nullable(),
    last_success_at: z.string().nullable(),
    counts: z.object({ active: z.number().int(), inactive: z.number().int(), error: z.number().int(), pending: z.number().int() }),
    accounts: z.array(Account),
    groups: z.array(z.object({ group_id: Id, display_name: z.string(), remote_id: z.string(), last_synced_at: z.string() })),
  })
  .openapi("AppProvisioning");

async function status(tx: Tx, appId: string): Promise<z.infer<typeof Provisioning>> {
  const prov = await tx.selectFrom("app_provisioning").selectAll().where("app_id", "=", appId).executeTakeFirst();
  const accounts = await tx
    .selectFrom("provisioned_accounts")
    .innerJoin("users", "users.id", "provisioned_accounts.user_id")
    .select(["provisioned_accounts.user_id", "users.email", "users.given_name", "users.family_name", "provisioned_accounts.state", "provisioned_accounts.remote_id", "provisioned_accounts.last_synced_at", "provisioned_accounts.last_error"])
    .where("provisioned_accounts.app_id", "=", appId)
    .execute();
  const pendingRows = prov?.enabled
    ? await tx
        .selectFrom("jobs")
        .select("payload")
        .where("kind", "=", "scim.user")
        .where("status", "in", ["queued", "running"])
        .where(sql<string>`payload->>'app_id'`, "=", appId)
        .execute()
    : [];
  const pendingIds = new Set(pendingRows.map((j) => (j.payload as unknown as { app_id: string; user_id: string })).filter((p) => p.app_id === appId).map((p) => p.user_id));
  const known = new Set(accounts.map((a) => a.user_id));
  const pendingUsers = [...pendingIds].filter((id) => !known.has(id));
  const pendingInfo = pendingUsers.length ? await tx.selectFrom("users").select(["id", "email", "given_name", "family_name"]).where("id", "in", pendingUsers).execute() : [];
  const name = (u: { given_name: string; family_name: string; email: string }) => `${u.given_name} ${u.family_name}`.trim() || u.email;
  const rows: z.infer<typeof Account>[] = [
    ...pendingInfo.map((u) => ({ user_id: u.id, email: u.email, display_name: name(u), state: "pending" as const, remote_id: null, last_synced_at: null, last_error: "" })),
    ...accounts.map((a) => ({
      user_id: a.user_id,
      email: a.email,
      display_name: name(a),
      state: pendingIds.has(a.user_id) && a.state !== "error" ? ("pending" as const) : a.state,
      remote_id: a.remote_id,
      last_synced_at: iso(a.last_synced_at),
      last_error: a.last_error,
    })),
  ].sort((x, y) => (x.state === "error" ? -1 : 0) - (y.state === "error" ? -1 : 0) || x.email.localeCompare(y.email));
  const groups = await tx.selectFrom("provisioned_groups").select(["group_id", "display_name", "remote_id", "last_synced_at"]).where("app_id", "=", appId).orderBy("display_name").execute();
  const count = (s: string) => rows.filter((r) => r.state === s).length;
  return {
    configured: !!prov,
    enabled: prov?.enabled ?? false,
    base_url: prov?.base_url ?? "",
    push_groups: prov?.push_groups ?? true,
    on_unassign: prov?.on_unassign ?? "deactivate",
    last_error: prov?.last_error ?? "",
    last_error_at: prov?.last_error_at ? iso(prov.last_error_at) : null,
    last_success_at: prov?.last_success_at ? iso(prov.last_success_at) : null,
    counts: { active: count("active"), inactive: count("inactive"), error: count("error"), pending: count("pending") },
    accounts: rows.slice(0, 500),
    groups: groups.map((g) => ({ ...g, last_synced_at: iso(g.last_synced_at) })),
  };
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

async function safeBase(c: Context<Env>, raw: string) {
  try {
    return (await assertSafeUrl(raw, { allowPrivate: c.get("deps").cfg.allowPrivateOutbound })).toString().replace(/\/+$/, "");
  } catch (err) {
    if (err instanceof UnsafeUrlError) throw badRequest("unsafe_url", err.message);
    throw err;
  }
}

async function probe(client: ScimClient) {
  try {
    await client.probe();
  } catch (err) {
    if (err instanceof ScimError) throw new ApiError(422, "scim_unreachable", err.message);
    throw err;
  }
}

export function registerProvisioningRoutes(app: App) {
  const idParam = { params: z.object({ id: Id }) };
  const ok = { 200: json(Provisioning), ...problemResponses };
  const appOr404 = async (tx: Tx, id: string) => {
    const a = await tx.selectFrom("applications").select(["id", "name"]).where("id", "=", id).executeTakeFirst();
    if (!a) throw notFound("Application");
    return a;
  };

  app.openapi(
    createRoute({ method: "get", path: "/v1/apps/{id}/provisioning", tags: ["Provisioning"], summary: "Provisioning settings and every account's state", security: bearer, request: idParam, responses: ok }),
    async (c) => {
      const p = requirePermission(c, "apps:read");
      const { id } = c.req.valid("param");
      return c.json(await c.get("deps").db.tenant(p.orgId, async (tx) => (await appOr404(tx, id), status(tx, id))), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apps/{id}/provisioning/test",
      tags: ["Provisioning"],
      summary: "Check a SCIM endpoint and token (the saved ones if omitted)",
      security: bearer,
      request: { ...idParam, ...body(z.object({ base_url: z.string().max(500).optional(), token: z.string().max(4000).optional() })) },
      responses: { 204: { description: "The app answered as a SCIM 2.0 service" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const saved = await deps.db.tenant(p.orgId, async (tx) => (await appOr404(tx, id), tx.selectFrom("app_provisioning").selectAll().where("app_id", "=", id).executeTakeFirst()));
      const base = await safeBase(c, input.base_url ?? saved?.base_url ?? "");
      const token = input.token ?? (saved ? deps.sealer.open(saved.token, tokenAad(id)).toString() : "");
      if (!token) throw badRequest("token_required", "A bearer token is required");
      await probe(new ScimClient(base, token));
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/apps/{id}/provisioning",
      tags: ["Provisioning"],
      summary: "Configure SCIM provisioning (requires recent MFA)",
      description: "Turning it on converges every assigned person right away. The token is required the first time and is never returned.",
      security: bearer,
      request: {
        ...idParam,
        ...body(
          z.object({
            base_url: z.string().max(500).openapi({ example: "https://api.example.com/scim/v2" }),
            token: z.string().min(1).max(4000).optional(),
            enabled: z.boolean(),
            push_groups: z.boolean().default(true),
            on_unassign: z.enum(["deactivate", "delete"]).default("deactivate"),
          }),
        ),
      },
      responses: ok,
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const base = await safeBase(c, input.base_url);
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const a = await appOr404(tx, id);
        const before = await tx.selectFrom("app_provisioning").selectAll().where("app_id", "=", id).executeTakeFirst();
        if (!before && !input.token) throw badRequest("token_required", "A bearer token is required");
        const token = input.token ? deps.sealer.seal(Buffer.from(input.token), tokenAad(id)) : before!.token;
        const row = { base_url: base, token, enabled: input.enabled, push_groups: input.push_groups, on_unassign: input.on_unassign, updated_at: new Date() };
        await tx
          .insertInto("app_provisioning")
          .values({ app_id: id, org_id: p.orgId, ...row })
          .onConflict((oc) => oc.column("app_id").doUpdateSet({ ...row, ...(input.token ? { last_error: "", last_error_at: null } : {}) }))
          .execute();
        if (input.enabled) await touchApp(tx, p.orgId, id);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: before ? "app.provisioning_updated" : "app.provisioning_configured",
          target: { type: "application", id, display: a.name },
          details: { base_url: base, enabled: input.enabled, push_groups: input.push_groups, on_unassign: input.on_unassign, token_rotated: !!input.token && !!before },
        });
        return status(tx, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/apps/{id}/provisioning/sync", tags: ["Provisioning"], summary: "Re-check every account now", security: bearer, request: idParam, responses: ok }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await appOr404(tx, id);
        await touchApp(tx, p.orgId, id);
        return status(tx, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apps/{id}/provisioning/accounts/{userId}/retry",
      tags: ["Provisioning"],
      summary: "Retry one person's account",
      security: bearer,
      request: { params: z.object({ id: Id, userId: Id }) },
      responses: ok,
    }),
    async (c) => {
      const p = requirePermission(c, "apps:write");
      const { id, userId } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await appOr404(tx, id);
        await touchUsers(tx, p.orgId, [userId], [id]);
        return status(tx, id);
      });
      return c.json(out, 200);
    },
  );
}

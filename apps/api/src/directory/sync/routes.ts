import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { randomBytes } from "node:crypto";
import type { App, Env, Principal } from "../../context.js";
import { audit } from "../../audit/record.js";
import { verifiedFactorTypes } from "../../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../../auth/guard.js";
import { hashToken } from "../../auth/tokens.js";
import type { Tx } from "../../platform/db.js";
import { isUniqueViolation } from "../../platform/db.js";
import { ApiError, badRequest, conflict, notFound } from "../../platform/errors.js";
import { newId } from "../../platform/ids.js";
import { enqueue } from "../../platform/jobs.js";
import { bearer, body, Id, iso, json, patchOf, problemResponses } from "../../schemas.js";
import { PROVIDER_NAME, summarize, type Plan, type Remote } from "./plan.js";
import { EntraConfig, fetchDirectory, GoogleConfig, GoogleKey, ProviderError } from "./providers.js";
import { loadConnection, loadLocal, planFor, remoteFor, secretAad, syncDedupeKey } from "./service.js";
import { fetchLdap, LdapConfigSchema } from "./ldap.js";

const Provider = z.enum(["google", "entra", "scim", "ldap"]);
const GoogleCreds = z.object({
  provider: z.literal("google"),
  admin_email: z.email(),
  customer_id: z.string().regex(/^[A-Za-z0-9_]+$/).default("my_customer"),
  service_account_key: z.string().max(20_000).openapi({ description: "The service account's JSON key file contents" }),
});
const EntraCreds = z.object({
  provider: z.literal("entra"),
  tenant_id: z.string().max(255),
  client_id: z.uuid(),
  client_secret: z.string().min(1).max(1000),
});
const LdapCreds = LdapConfigSchema.extend({
  provider: z.literal("ldap"),
  bind_password: z.string().min(1).max(1000).openapi({ description: "The service account's password (read-only account)" }),
});
const Creds = z.discriminatedUnion("provider", [GoogleCreds, EntraCreds, LdapCreds]);
const SettingsIn = z.object({
  enabled: z.boolean().default(false).openapi({ description: "Scheduled syncs. New connections start off so you can preview first." }),
  sync_groups: z.boolean().default(true),
  group_filter: z.array(z.string().max(200)).max(100).default([]).openapi({ description: "Remote group IDs to sync; empty = whole directory" }),
  deprovision: z.enum(["suspend", "none"]).default("suspend"),
  invite_new_users: z.boolean().default(true),
  interval_minutes: z.number().int().min(15).max(1440).default(60),
});

const Connection = z
  .object({
    id: Id,
    provider: Provider,
    provider_name: z.string(),
    name: z.string(),
    account: z.string().openapi({ description: "Admin email (Google) or tenant (Entra) the connection reads" }),
    ...SettingsIn.shape,
    enabled: z.boolean(),
    last_sync_at: z.string().nullable(),
    next_sync_at: z.string().nullable(),
    last_status: z.enum(["never", "ok", "error", "needs_approval"]),
    last_result: z.record(z.string(), z.unknown()),
    last_error: z.string(),
    syncing: z.boolean(),
    linked_users: z.number().int(),
    linked_groups: z.number().int(),
    scim: z
      .object({ base_url: z.string(), token_hint: z.string(), last_request_at: z.string().nullable(), deactivations_allowed_until: z.string().nullable() })
      .nullable()
      .openapi({ description: "For SCIM connections: where the IdP sends changes" }),
    created_at: z.string(),
  })
  .openapi("DirectoryConnection");

const Probe = z
  .object({ users: z.number().int(), active_users: z.number().int(), groups: z.array(z.object({ id: z.string(), name: z.string(), members: z.number().int() })) })
  .openapi("DirectoryProbe");

const PlanOut = z
  .object({
    summary: z.record(z.string(), z.number()),
    guard: z.object({ tripped: z.boolean(), suspensions: z.number().int(), threshold: z.number().int() }),
    create_users: z.array(z.object({ email: z.string(), name: z.string(), active: z.boolean() })),
    link_users: z.array(z.object({ email: z.string() })),
    update_users: z.array(z.object({ email: z.string(), changes: z.record(z.string(), z.object({ from: z.string(), to: z.string() })) })),
    suspend_users: z.array(z.object({ email: z.string(), reason: z.string() })),
    reactivate_users: z.array(z.object({ email: z.string() })),
    groups: z.array(z.object({ name: z.string(), action: z.enum(["create", "link", "update", "members"]), add: z.number().int(), remove: z.number().int() })),
    skipped: z.array(z.object({ email: z.string(), reason: z.string() })),
  })
  .openapi("DirectoryPlan");

function credentials(c: z.infer<typeof Creds>): { config: Record<string, unknown>; secret: string } {
  if (c.provider === "ldap") {
    const { provider: _p, bind_password, ...config } = c;
    return { config: LdapConfigSchema.parse(config), secret: bind_password };
  }
  if (c.provider === "google") {
    let key: z.infer<typeof GoogleKey>;
    try {
      key = GoogleKey.parse(JSON.parse(c.service_account_key));
    } catch {
      throw badRequest("invalid_key", "That isn't a Google service account JSON key file");
    }
    const config = { admin_email: c.admin_email, customer_id: c.customer_id, service_account: key.client_email };
    GoogleConfig.parse(config);
    return { config, secret: c.service_account_key };
  }
  const config = { tenant_id: c.tenant_id, client_id: c.client_id };
  const r = EntraConfig.safeParse(config);
  if (!r.success) throw badRequest("invalid_tenant", r.error.issues[0]?.message ?? "Invalid tenant");
  return { config, secret: c.client_secret };
}

async function probe(fetcher: () => Promise<Remote>): Promise<z.infer<typeof Probe>> {
  let remote: Remote;
  try {
    remote = await fetcher();
  } catch (err) {
    if (err instanceof ProviderError) throw new ApiError(422, "directory_unreachable", err.message);
    throw err;
  }
  return {
    users: remote.users.length,
    active_users: remote.users.filter((u) => u.active).length,
    groups: remote.groups.map((g) => ({ id: g.external_id, name: g.name, members: g.member_ids.length })).sort((a, b) => a.name.localeCompare(b.name)),
  };
}

const CAP = 100;
function planOut(p: Plan): z.infer<typeof PlanOut> {
  return {
    summary: summarize(p),
    guard: p.guard,
    create_users: p.create_users.slice(0, CAP).map((u) => ({ email: u.email, name: `${u.given_name} ${u.family_name}`.trim(), active: u.active })),
    link_users: p.link_users.slice(0, CAP).map((u) => ({ email: u.email })),
    update_users: p.update_users.slice(0, CAP).map((u) => ({ email: u.email, changes: u.changes as Record<string, { from: string; to: string }> })),
    suspend_users: p.suspend_users.slice(0, 500).map((u) => ({ email: u.email, reason: u.reason })),
    reactivate_users: p.reactivate_users.slice(0, CAP).map((u) => ({ email: u.email })),
    groups: [
      ...p.create_groups.map((g) => ({ name: g.name, action: "create" as const, add: 0, remove: 0 })),
      ...p.link_groups.map((g) => ({ name: g.name, action: "link" as const, add: 0, remove: 0 })),
      ...p.update_groups.map((g) => ({ name: g.changes.name?.to ?? g.name, action: "update" as const, add: 0, remove: 0 })),
      ...p.membership.map((m) => ({ name: m.group_name, action: "members" as const, add: m.add.length, remove: m.remove.length })),
    ].slice(0, CAP),
    skipped: p.skipped.slice(0, CAP),
  };
}

async function listOut(tx: Tx, apiPublicUrl = ""): Promise<z.infer<typeof Connection>[]> {
  const rows = await tx.selectFrom("directory_connections").selectAll().orderBy("created_at").execute();
  const counts = await tx.selectFrom("directory_links").select(["connection_id", "kind"]).select((eb) => eb.fn.countAll<number>().as("n")).groupBy(["connection_id", "kind"]).execute();
  const busy = new Set(
    (await tx.selectFrom("jobs").select("dedupe_key").where("kind", "=", "directory.sync").where("status", "in", ["queued", "running"]).execute()).map((j) => j.dedupe_key),
  );
  const n = (id: string, kind: string) => Number(counts.find((x) => x.connection_id === id && x.kind === kind)?.n ?? 0);
  return rows.map((r) => {
    const cfg = r.config as Record<string, string>;
    return {
      id: r.id,
      provider: r.provider,
      provider_name: PROVIDER_NAME[r.provider],
      name: r.name,
      account: r.provider === "google" ? cfg.admin_email ?? "" : r.provider === "entra" ? cfg.tenant_id ?? "" : r.provider === "ldap" ? `${cfg.url ?? ""} (${cfg.base_dn ?? ""})${(cfg as { password_auth?: boolean }).password_auth ? ", directory passwords" : ""}` : "",
      enabled: r.enabled,
      sync_groups: r.sync_groups,
      group_filter: r.group_filter,
      deprovision: r.deprovision,
      invite_new_users: r.invite_new_users,
      interval_minutes: r.interval_minutes,
      last_sync_at: r.last_sync_at ? iso(r.last_sync_at) : null,
      next_sync_at: r.enabled && r.provider !== "scim" ? new Date((r.last_sync_at?.getTime() ?? Date.now()) + (r.last_sync_at ? r.interval_minutes * 60_000 : 0)).toISOString() : null,
      last_status: r.last_status,
      last_result: r.last_result as Record<string, unknown>,
      last_error: r.last_error,
      syncing: busy.has(syncDedupeKey(r.id)),
      linked_users: n(r.id, "user"),
      linked_groups: n(r.id, "group"),
      scim:
        r.provider === "scim"
          ? {
              base_url: `${apiPublicUrl}/scim/v2`,
              token_hint: r.token_hint,
              last_request_at: r.last_request_at ? iso(r.last_request_at) : null,
              deactivations_allowed_until: r.deactivations_allowed_until && r.deactivations_allowed_until > new Date() ? iso(r.deactivations_allowed_until) : null,
            }
          : null,
      created_at: iso(r.created_at),
    };
  });
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

const newScimToken = () => {
  const token = `nxscim_${randomBytes(32).toString("base64url")}`;
  return { token, set: { token_hash: hashToken(token), token_hint: token.slice(-4) } };
};
const ScimCredentials = z.object({ base_url: z.string(), token: z.string().openapi({ description: "Shown once. Paste it into your IdP as the bearer token." }) }).openapi("ScimCredentials");

export function registerDirectorySyncRoutes(app: App) {
  const list = { 200: json(z.object({ data: z.array(Connection) })), ...problemResponses };
  const idParam = { params: z.object({ id: Id }) };

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/directory/scim",
      tags: ["Directory sync"],
      summary: "Let your IdP push users and groups with SCIM (requires recent MFA)",
      description: "For Okta, Microsoft Entra ID, JumpCloud, OneLogin and others. Returns the SCIM base URL and a bearer token, shown once.",
      security: bearer,
      request: body(
        z.object({
          name: z.string().trim().min(1).max(100),
          deprovision: z.enum(["suspend", "none"]).default("suspend").openapi({ description: "What deactivating someone at the IdP does in Nexus" }),
          invite_new_users: z.boolean().default(true).openapi({ description: "Email new people an invitation (skipped when your IdP signs them in)" }),
        }),
      ),
      responses: { 201: json(z.object({ data: z.array(Connection), scim: ScimCredentials }), "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "directory:sync");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const id = newId();
      const t = newScimToken();
      try {
        const data = await deps.db.tenant(p.orgId, async (tx) => {
          await stepUp(c, tx, p);
          await tx
            .insertInto("directory_connections")
            .values({ id, org_id: p.orgId, provider: "scim", name: input.name, config: "{}", secret: null, enabled: true, sync_groups: true, deprovision: input.deprovision, invite_new_users: input.invite_new_users, created_by: p.userId, ...t.set })
            .execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "directory.connection_created",
            target: { type: "directory_connection", id, display: input.name },
            details: { provider: "scim", deprovision: input.deprovision, invite_new_users: input.invite_new_users },
          });
          return listOut(tx, deps.cfg.apiPublicUrl);
        });
        return c.json({ data, scim: { base_url: `${deps.cfg.apiPublicUrl}/scim/v2`, token: t.token } }, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "A connection with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/directory/connections/{id}/scim-token",
      tags: ["Directory sync"],
      summary: "Replace a SCIM connection's bearer token (requires recent MFA)",
      description: "The old token stops working immediately. Update it in your IdP.",
      security: bearer,
      request: idParam,
      responses: { 200: json(ScimCredentials), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "directory:sync");
      const { id } = c.req.valid("param");
      const deps = c.get("deps");
      const t = newScimToken();
      await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const r = await tx.updateTable("directory_connections").set({ ...t.set, updated_at: new Date() }).where("id", "=", id).where("provider", "=", "scim").returning("name").executeTakeFirst();
        if (!r) throw notFound("SCIM connection");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "directory.scim_token_rotated", target: { type: "directory_connection", id, display: r.name } });
      });
      return c.json({ base_url: `${deps.cfg.apiPublicUrl}/scim/v2`, token: t.token }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/directory/test",
      tags: ["Directory sync"],
      summary: "Check credentials and list the directory's groups (nothing is saved)",
      security: bearer,
      request: body(Creds),
      responses: { 200: json(Probe), ...problemResponses },
    }),
    async (c) => {
      requirePermission(c, "directory:sync");
      const { config, secret } = credentials(c.req.valid("json"));
      const provider = c.req.valid("json").provider;
      return c.json(await probe(() => (provider === "ldap" ? fetchLdap(c.get("deps"), config, secret, { groups: true }) : fetchDirectory(c.get("deps").cfg, provider, config, secret, { groups: true }))), 200);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/directory/connections", tags: ["Directory sync"], summary: "Directory connections and their last sync", security: bearer, responses: list }),
    async (c) => {
      const p = requirePermission(c, "users:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => listOut(tx, c.get("deps").cfg.apiPublicUrl)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/directory/connections",
      tags: ["Directory sync"],
      summary: "Connect Google Workspace or Microsoft Entra ID (requires recent MFA)",
      security: bearer,
      request: body(z.intersection(Creds, SettingsIn.extend({ name: z.string().trim().min(1).max(100) }))),
      responses: { 201: json(z.object({ data: z.array(Connection) }), "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "directory:sync");
      const input = c.req.valid("json");
      const { config, secret } = credentials(input);
      const deps = c.get("deps");
      const id = newId();
      try {
        const data = await deps.db.tenant(p.orgId, async (tx) => {
          await stepUp(c, tx, p);
          await tx
            .insertInto("directory_connections")
            .values({
              id,
              org_id: p.orgId,
              provider: input.provider,
              name: input.name,
              config: JSON.stringify(config),
              secret: deps.sealer.seal(Buffer.from(secret), secretAad(id)),
              enabled: input.enabled,
              sync_groups: input.sync_groups,
              group_filter: input.group_filter,
              deprovision: input.deprovision,
              invite_new_users: input.invite_new_users,
              interval_minutes: input.interval_minutes,
              created_by: p.userId,
            })
            .execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "directory.connection_created",
            target: { type: "directory_connection", id, display: input.name },
            details: { provider: input.provider, config, enabled: input.enabled, deprovision: input.deprovision },
          });
          return listOut(tx, c.get("deps").cfg.apiPublicUrl);
        });
        return c.json({ data }, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "A connection with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/directory/connections/{id}",
      tags: ["Directory sync"],
      summary: "Change a connection's settings or credentials (requires recent MFA)",
      security: bearer,
      request: {
        ...idParam,
        ...body(
          patchOf(SettingsIn).extend({
            name: z.string().trim().min(1).max(100).optional(),
            credentials: Creds.optional(),
            ldap_bind_password: z.string().min(1).max(1000).optional().openapi({ description: "LDAP: rotate the service account's password (other settings unchanged)" }),
            ldap_password_auth: z.boolean().optional().openapi({ description: "LDAP: people sign in with their directory password" }),
          }),
        ),
      },
      responses: list,
    }),
    async (c) => {
      const p = requirePermission(c, "directory:sync");
      const { id } = c.req.valid("param");
      const { credentials: creds, ldap_bind_password, ldap_password_auth, ...set } = c.req.valid("json");
      const deps = c.get("deps");
      const data = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const before = await loadConnection(tx, id);
        if (!before) throw notFound("Connection");
        let secretSet = {};
        if ((ldap_bind_password || ldap_password_auth !== undefined) && before.provider !== "ldap") throw badRequest("provider_mismatch", "Those settings are for LDAP connections");
        if (ldap_bind_password) secretSet = { secret: deps.sealer.seal(Buffer.from(ldap_bind_password), secretAad(id)) };
        if (ldap_password_auth !== undefined) secretSet = { ...secretSet, config: JSON.stringify({ ...(before.config as object), password_auth: ldap_password_auth }) };
        if (creds) {
          if (creds.provider !== before.provider) throw badRequest("provider_mismatch", "Credentials are for a different provider");
          const { config, secret } = credentials(creds);
          secretSet = { config: JSON.stringify(config), secret: deps.sealer.seal(Buffer.from(secret), secretAad(id)) };
        }
        await tx.updateTable("directory_connections").set({ ...set, ...secretSet, updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "directory.connection_updated",
          target: { type: "directory_connection", id, display: set.name ?? before.name },
          details: { changes: { ...set, ...(ldap_password_auth !== undefined ? { password_auth: ldap_password_auth } : {}) }, credentials_rotated: !!creds || !!ldap_bind_password },
        });
        return listOut(tx, c.get("deps").cfg.apiPublicUrl);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/directory/connections/{id}",
      tags: ["Directory sync"],
      summary: "Disconnect (people and groups stay; they're just no longer synced). Requires recent MFA.",
      security: bearer,
      request: idParam,
      responses: list,
    }),
    async (c) => {
      const p = requirePermission(c, "directory:sync");
      const { id } = c.req.valid("param");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const r = await tx.deleteFrom("directory_connections").where("id", "=", id).returning("name").executeTakeFirst();
        if (!r) throw notFound("Connection");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "directory.connection_deleted", target: { type: "directory_connection", id, display: r.name } });
        return listOut(tx, c.get("deps").cfg.apiPublicUrl);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/directory/connections/{id}/test", tags: ["Directory sync"], summary: "Check a saved connection and list its groups", security: bearer, request: idParam, responses: { 200: json(Probe), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "directory:sync");
      const deps = c.get("deps");
      const conn = await deps.db.tenant(p.orgId, (tx) => loadConnection(tx, c.req.valid("param").id));
      if (!conn) throw notFound("Connection");
      return c.json(await probe(() => remoteFor(deps, { ...conn, sync_groups: true })), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/directory/connections/{id}/preview",
      tags: ["Directory sync"],
      summary: "Dry run: exactly what a sync would change now",
      security: bearer,
      request: idParam,
      responses: { 200: json(PlanOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "directory:sync");
      const deps = c.get("deps");
      const conn = await deps.db.tenant(p.orgId, (tx) => loadConnection(tx, c.req.valid("param").id));
      if (!conn) throw notFound("Connection");
      let remote: Remote;
      try {
        remote = await remoteFor(deps, conn);
      } catch (err) {
        if (err instanceof ProviderError) throw new ApiError(422, "directory_unreachable", err.message);
        throw err;
      }
      const plan = await deps.db.tenant(p.orgId, async (tx) => planFor(conn, remote, await loadLocal(tx, conn.id)));
      return c.json(planOut(plan), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/directory/connections/{id}/sync",
      tags: ["Directory sync"],
      summary: "Sync now",
      description: "Runs in the background. `approved_suspensions` approves a run held by the safety limit (requires recent MFA): up to that many people may be suspended.",
      security: bearer,
      request: { ...idParam, ...body(z.object({ approved_suspensions: z.number().int().min(0).max(100_000).optional() })) },
      responses: { 202: json(z.object({ data: z.array(Connection) }), "Queued"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "directory:sync");
      const { id } = c.req.valid("param");
      const { approved_suspensions } = c.req.valid("json");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const conn = await loadConnection(tx, id);
        if (!conn) throw notFound("Connection");
        if (conn.provider === "scim") {
          // Nothing to pull: approving lets held deactivations through for the next hour.
          if (approved_suspensions === undefined) throw badRequest("scim_push", "A SCIM connection is updated by your identity provider; there's nothing for Nexus to fetch");
          await stepUp(c, tx, p);
          await tx.updateTable("directory_connections").set({ deactivations_allowed_until: new Date(Date.now() + 3600_000), last_status: "ok", last_error: "" }).where("id", "=", id).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "directory.mass_change_approved", target: { type: "directory_connection", id, display: conn.name }, details: { scim: true, for_minutes: 60 } });
          return listOut(tx, c.get("deps").cfg.apiPublicUrl);
        }
        if (approved_suspensions !== undefined) {
          await stepUp(c, tx, p);
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
            type: "directory.mass_change_approved",
            target: { type: "directory_connection", id, display: conn.name },
            details: { approved_suspensions },
          });
        }
        await enqueue(tx, p.orgId, "directory.sync", { connection_id: id, trigger: "manual", ...(approved_suspensions !== undefined ? { approved_suspensions } : {}) }, { dedupeKey: syncDedupeKey(id), maxAttempts: 3 });
        return listOut(tx, c.get("deps").cfg.apiPublicUrl);
      });
      return c.json({ data }, 202);
    },
  );
}

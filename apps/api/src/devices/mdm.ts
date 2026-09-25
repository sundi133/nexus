import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { sql } from "kysely";
import type { App, Deps, Env, Principal, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { ProviderError } from "../directory/sync/providers.js";
import { notifyRoles } from "../notify/send.js";
import { isUniqueViolation, type Tx } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { enqueue, registerJobHandler, type JobRunner } from "../platform/jobs.js";
import { UnsafeUrlError } from "../platform/outbound.js";
import { bearer, body, Id, iso, isoOrNull, json, patchOf, problemResponses } from "../schemas.js";
import { fetchMdm, IntuneConfig, JamfConfig, type MdmDevice } from "./mdm-providers.js";
import { reevaluateAll } from "./service.js";

/**
 * MDM signals: Microsoft Intune and Jamf Pro tell Nexus which devices they
 * manage and whether those are compliant. Matched to Nexus devices by serial
 * number; used by the "managed and compliant in your MDM" policy and shown
 * on each device. Also: which MDM devices have no Nexus agent yet (coverage).
 */

export const mdmSecretAad = (id: string) => `mdm_connection:${id}`;
import { MDM_PROVIDER as PROVIDER, mdmRowsForDevice } from "./mdm-signals.js";
const SYSTEM_META: RequestMeta = { ip: "", userAgent: "nexus-mdm-sync", requestId: "" };

// ---- Sync ------------------------------------------------------------------------------------

export async function syncMdm(deps: Deps, orgId: string, connectionId: string) {
  const conn = await deps.db.tenant(orgId, (tx) => tx.selectFrom("mdm_connections").selectAll().where("id", "=", connectionId).executeTakeFirst());
  if (!conn) return;
  let devices: MdmDevice[];
  try {
    devices = await fetchMdm(deps.cfg, conn.provider, conn.config, deps.sealer.open(conn.secret, mdmSecretAad(conn.id)).toString());
  } catch (err) {
    const message = err instanceof ProviderError || err instanceof UnsafeUrlError ? err.message : `Unexpected error: ${(err as Error).message}`;
    await deps.db.tenant(orgId, async (tx) => {
      await tx.updateTable("mdm_connections").set({ last_sync_at: new Date(), last_status: "error", last_error: message.slice(0, 500) }).where("id", "=", conn.id).execute();
      if (conn.last_status !== "error") {
        await notifyRoles(tx, orgId, ["owner", "admin"], {
          category: "devices.mdm",
          severity: "warning",
          title: `Can't read ${conn.name}`,
          body: `${message}. Device signals from ${PROVIDER[conn.provider]} are stale until this is fixed.`,
          entity: { type: "mdm_connection", id: conn.id },
          link: "/mdm",
        });
      }
    });
    return;
  }
  await deps.db.tenant(orgId, async (tx) => {
    const now = new Date();
    for (let i = 0; i < devices.length; i += 500) {
      const chunk = devices.slice(i, i + 500).map((d) => ({ org_id: orgId, connection_id: conn.id, ...d, updated_at: now }));
      await tx
        .insertInto("mdm_devices")
        .values(chunk)
        .onConflict((oc) =>
          oc.columns(["connection_id", "external_id"]).doUpdateSet((eb) => ({
            serial: eb.ref("excluded.serial"),
            name: eb.ref("excluded.name"),
            platform: eb.ref("excluded.platform"),
            os_version: eb.ref("excluded.os_version"),
            user_email: eb.ref("excluded.user_email"),
            managed: eb.ref("excluded.managed"),
            compliant: eb.ref("excluded.compliant"),
            compliance_detail: eb.ref("excluded.compliance_detail"),
            encrypted: eb.ref("excluded.encrypted"),
            last_contact_at: eb.ref("excluded.last_contact_at"),
            management_id: eb.ref("excluded.management_id"),
            updated_at: eb.ref("excluded.updated_at"),
          })),
        )
        .execute();
    }
    // Gone from the MDM: forget them.
    await tx.deleteFrom("mdm_devices").where("connection_id", "=", conn.id).where("updated_at", "<", now).execute();
    // Match to Nexus devices by serial number.
    await sql`
      UPDATE mdm_devices m SET device_id = d.id
      FROM devices d
      WHERE m.connection_id = ${conn.id} AND m.serial <> '' AND d.status = 'active' AND lower(d.serial) = lower(m.serial)`.execute(tx);
    const counts = (
      await sql<{ total: number; matched: number; noncompliant: number }>`
        SELECT count(*)::int AS total, count(device_id)::int AS matched, count(*) FILTER (WHERE compliant = false OR NOT managed)::int AS noncompliant
        FROM mdm_devices WHERE connection_id = ${conn.id}`.execute(tx)
    ).rows[0]!;
    const result = { devices: counts.total, matched: counts.matched, without_agent: counts.total - counts.matched, noncompliant: counts.noncompliant };
    await tx.updateTable("mdm_connections").set({ last_sync_at: now, last_status: "ok", last_error: "", last_result: JSON.stringify(result) }).where("id", "=", conn.id).execute();
    await audit(tx, orgId, { meta: SYSTEM_META }, { type: "device.mdm_synced", actor: { type: "system", id: null, display: PROVIDER[conn.provider] }, target: { type: "mdm_connection", id: conn.id, display: conn.name }, details: result });
    await reevaluateAll(tx, { meta: SYSTEM_META });
  });
}

registerJobHandler("mdm.sync", async (deps, job) => {
  await syncMdm(deps, job.org_id, String((job.payload as { connection_id: string }).connection_id));
});
const syncKey = (id: string) => `mdm.sync:${id}`;

export function scheduleMdmSyncs(jobs: JobRunner, deps: Deps) {
  let last = 0;
  jobs.onTick(async () => {
    if (Date.now() - last < 60_000) return;
    last = Date.now();
    const due = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; connection_id: string }>`SELECT * FROM nexus_due_mdm_syncs()`.execute(tx)).rows);
    for (const d of due) await deps.db.tenant(d.org_id, (tx) => enqueue(tx, d.org_id, "mdm.sync", { connection_id: d.connection_id }, { dedupeKey: syncKey(d.connection_id), maxAttempts: 2 }));
  });
}

// ---- API -------------------------------------------------------------------------------------

const Credentials = z.discriminatedUnion("provider", [
  IntuneConfig.extend({ provider: z.literal("intune"), client_secret: z.string().min(1).max(1000) }),
  JamfConfig.extend({ provider: z.literal("jamf"), client_secret: z.string().min(1).max(1000) }),
]);
const split = (c: z.infer<typeof Credentials>) => {
  const { provider, client_secret, ...config } = c;
  return { provider, secret: client_secret, config };
};

const Connection = z
  .object({
    id: Id,
    provider: z.enum(["intune", "jamf"]),
    provider_name: z.string(),
    name: z.string(),
    account: z.string().openapi({ description: "Tenant (Intune) or Jamf URL" }),
    enabled: z.boolean(),
    interval_minutes: z.number().int(),
    last_sync_at: z.string().nullable(),
    last_status: z.enum(["never", "ok", "error"]),
    last_error: z.string(),
    devices: z.number().int(),
    matched: z.number().int().openapi({ description: "MDM devices that are also Nexus devices (same serial number)" }),
    without_agent: z.number().int().openapi({ description: "MDM devices with no Nexus agent: deploy it from the MDM" }),
    noncompliant: z.number().int(),
    syncing: z.boolean(),
    created_at: z.string(),
  })
  .openapi("MdmConnection");
const MdmDeviceOut = z
  .object({
    external_id: z.string(),
    name: z.string(),
    serial: z.string(),
    platform: z.string(),
    os_version: z.string(),
    user_email: z.string(),
    managed: z.boolean(),
    compliant: z.boolean().nullable(),
    compliance_detail: z.string(),
    encrypted: z.boolean().nullable(),
    last_contact_at: z.string().nullable(),
    device_id: Id.nullable(),
  })
  .openapi("MdmDevice");

async function listOut(tx: Tx): Promise<z.infer<typeof Connection>[]> {
  const rows = await tx.selectFrom("mdm_connections").selectAll().orderBy("created_at").execute();
  const busy = new Set((await tx.selectFrom("jobs").select("dedupe_key").where("kind", "=", "mdm.sync").where("status", "in", ["queued", "running"]).execute()).map((j) => j.dedupe_key));
  return rows.map((r) => {
    const cfg = r.config as Record<string, string>;
    const res = r.last_result as unknown as Record<string, number>;
    return {
      id: r.id,
      provider: r.provider,
      provider_name: PROVIDER[r.provider],
      name: r.name,
      account: r.provider === "intune" ? (cfg.tenant_id ?? "") : (cfg.base_url ?? ""),
      enabled: r.enabled,
      interval_minutes: r.interval_minutes,
      last_sync_at: isoOrNull(r.last_sync_at),
      last_status: r.last_status,
      last_error: r.last_error,
      devices: res.devices ?? 0,
      matched: res.matched ?? 0,
      without_agent: res.without_agent ?? 0,
      noncompliant: res.noncompliant ?? 0,
      syncing: busy.has(syncKey(r.id)),
      created_at: iso(r.created_at),
    };
  });
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

/** Tries the credentials before saving them, so a typo shows up now, not in an hour. */
async function probe(deps: Deps, c: z.infer<typeof Credentials>) {
  const { provider, secret, config } = split(c);
  try {
    return await fetchMdm(deps.cfg, provider, config, secret);
  } catch (err) {
    if (err instanceof ProviderError || err instanceof UnsafeUrlError) throw badRequest("mdm_unreachable", err.message);
    throw err;
  }
}

export function registerMdmRoutes(app: App) {
  const list = { 200: json(z.object({ data: z.array(Connection) })), ...problemResponses };
  const idParam = { params: z.object({ id: Id }) };

  app.openapi(createRoute({ method: "get", path: "/v1/mdm/connections", tags: ["Devices"], summary: "Connected MDMs (Intune, Jamf) and what they report", security: bearer, responses: list }), async (c) => {
    const p = requirePermission(c, "devices:read");
    return c.json({ data: await c.get("deps").db.tenant(p.orgId, listOut) }, 200);
  });

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/mdm/connections",
      tags: ["Devices"],
      summary: "Connect Microsoft Intune or Jamf Pro (read-only; requires recent MFA)",
      description: "The credentials are tried first. Intune needs an Entra app with DeviceManagementManagedDevices.Read.All; Jamf an API client with Read Computers.",
      security: bearer,
      request: body(z.object({ name: z.string().trim().min(1).max(100), credentials: Credentials, interval_minutes: z.number().int().min(15).max(1440).default(60) })),
      responses: { 201: json(z.object({ data: z.array(Connection), found: z.number().int() }), "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const found = await probe(deps, input.credentials);
      const { provider, secret, config } = split(input.credentials);
      const id = newId();
      try {
        const data = await deps.db.tenant(p.orgId, async (tx) => {
          await stepUp(c, tx, p);
          await tx
            .insertInto("mdm_connections")
            .values({ id, org_id: p.orgId, provider, name: input.name, config: JSON.stringify(config), secret: deps.sealer.seal(Buffer.from(secret), mdmSecretAad(id)), interval_minutes: input.interval_minutes, created_by: p.userId })
            .execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.mdm_connected", target: { type: "mdm_connection", id, display: input.name }, details: { provider, config, devices: found.length } });
          await enqueue(tx, p.orgId, "mdm.sync", { connection_id: id }, { dedupeKey: syncKey(id), maxAttempts: 2 });
          return listOut(tx);
        });
        return c.json({ data, found: found.length }, 201);
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict("name_taken", "A connection with this name already exists");
        throw err;
      }
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/mdm/connections/{id}",
      tags: ["Devices"],
      summary: "Change an MDM connection (requires recent MFA)",
      security: bearer,
      request: { ...idParam, ...body(patchOf(z.object({ name: z.string().trim().min(1).max(100), enabled: z.boolean(), interval_minutes: z.number().int().min(15).max(1440), credentials: Credentials }))) },
      responses: list,
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      const { credentials, ...rest } = c.req.valid("json");
      const deps = c.get("deps");
      if (credentials) await probe(deps, credentials);
      const data = await deps.db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const before = await tx.selectFrom("mdm_connections").select(["name", "provider"]).where("id", "=", id).executeTakeFirst();
        if (!before) throw notFound("MDM connection");
        let creds = {};
        if (credentials) {
          if (credentials.provider !== before.provider) throw badRequest("provider_mismatch", "These credentials are for a different MDM");
          const { secret, config } = split(credentials);
          creds = { config: JSON.stringify(config), secret: deps.sealer.seal(Buffer.from(secret), mdmSecretAad(id)) };
        }
        await tx.updateTable("mdm_connections").set({ ...rest, ...creds, updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.mdm_updated", target: { type: "mdm_connection", id, display: rest.name ?? before.name }, details: { changes: rest, credentials_replaced: !!credentials } });
        if (credentials || rest.enabled) await enqueue(tx, p.orgId, "mdm.sync", { connection_id: id }, { dedupeKey: syncKey(id), maxAttempts: 2 });
        if (rest.enabled === false) await reevaluateAll(tx, { meta: c.get("meta") }); // its signals no longer count
        return listOut(tx);
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(createRoute({ method: "delete", path: "/v1/mdm/connections/{id}", tags: ["Devices"], summary: "Disconnect an MDM (requires recent MFA)", security: bearer, request: idParam, responses: list }), async (c) => {
    const p = requirePermission(c, "devices:write");
    const { id } = c.req.valid("param");
    const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
      await stepUp(c, tx, p);
      const r = await tx.deleteFrom("mdm_connections").where("id", "=", id).returning("name").executeTakeFirst();
      if (!r) throw notFound("MDM connection");
      await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.mdm_disconnected", target: { type: "mdm_connection", id, display: r.name } });
      await reevaluateAll(tx, { meta: c.get("meta") });
      return listOut(tx);
    });
    return c.json({ data }, 200);
  });

  app.openapi(createRoute({ method: "post", path: "/v1/mdm/connections/{id}/sync", tags: ["Devices"], summary: "Read the MDM now", security: bearer, request: idParam, responses: { 202: json(z.object({ data: z.array(Connection) }), "Queued"), ...problemResponses } }), async (c) => {
    const p = requirePermission(c, "devices:write");
    const { id } = c.req.valid("param");
    const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
      if (!(await tx.selectFrom("mdm_connections").select("id").where("id", "=", id).executeTakeFirst())) throw notFound("MDM connection");
      await enqueue(tx, p.orgId, "mdm.sync", { connection_id: id }, { dedupeKey: syncKey(id), maxAttempts: 2 });
      return listOut(tx);
    });
    return c.json({ data }, 202);
  });

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/mdm/connections/{id}/devices",
      tags: ["Devices"],
      summary: "Devices the MDM manages",
      description: "`without_agent=true`: only those with no Nexus agent (deploy the agent from the MDM to cover them).",
      security: bearer,
      request: { ...idParam, query: z.object({ without_agent: z.enum(["true", "false"]).optional(), limit: z.coerce.number().int().min(1).max(1000).default(200) }) },
      responses: { 200: json(z.object({ data: z.array(MdmDeviceOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const { id } = c.req.valid("param");
      const q = c.req.valid("query");
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        let s = tx.selectFrom("mdm_devices").selectAll().where("connection_id", "=", id);
        if (q.without_agent === "true") s = s.where("device_id", "is", null);
        return s.orderBy("name").limit(q.limit).execute();
      });
      return c.json({ data: rows.map((r) => ({ ...r, last_contact_at: isoOrNull(r.last_contact_at) })) }, 200);
    },
  );
}

/** For a device's detail page: what each MDM says about it. */
export async function mdmForDevice(tx: Tx, device: { id: string; serial: string }) {
  const rows = await mdmRowsForDevice(tx, device);
  return rows.map((r) => ({ source: PROVIDER[r.provider], connection: r.connection, managed: r.managed, compliant: r.compliant, detail: r.compliance_detail, encrypted: r.encrypted, last_contact_at: isoOrNull(r.last_contact_at) }));
}

import { mdmForDevice } from "./mdm.js";
import { createRoute, z } from "@hono/zod-openapi";
import { randomBytes } from "node:crypto";
import { sql } from "kysely";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { assertDeviceInScope, requirePermission, requireSession, scopeGroups } from "../auth/guard.js";
import { hashToken } from "../auth/tokens.js";
import type { Tx } from "../platform/db.js";
import type { DevicePlatform } from "../platform/db-types.js";
import { badRequest, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { decodeCursor, pageOf } from "../platform/pagination.js";
import { bearer, body, Cursor, Id, iso, isoOrNull, json, page, problemResponses } from "../schemas.js";
import { CHECK_INFO, CHECK_KEYS, fixFor, PolicyParams, type CheckKey } from "./posture.js";
import { getPolicies, ONLINE_WINDOW_MS, reevaluateAll } from "./service.js";

const Platform = z.enum(["macos", "windows", "linux"]);
const ComplianceEnum = z.enum(["compliant", "non_compliant", "unknown"]);

const DeviceSummary = z
  .object({
    id: Id,
    hostname: z.string(),
    platform: Platform,
    os_name: z.string(),
    os_version: z.string(),
    model: z.string(),
    serial: z.string(),
    compliance: ComplianceEnum,
    failing_checks: z.array(z.string()),
    compliance_grace_until: z.string().nullable().openapi({ description: "Enforced checks are failing but within their grace period until then" }),
    online: z.boolean(),
    last_seen_at: z.string().nullable(),
    primary_user: z.object({ id: Id, display_name: z.string(), email: z.string() }).nullable(),
    enrolled_at: z.string(),
  })
  .openapi("Device");

const DeviceCheck = z
  .object({
    key: z.enum(CHECK_KEYS),
    title: z.string(),
    why: z.string(),
    status: z.enum(["pass", "fail", "unknown", "not_applicable"]),
    detail: z.string(),
    fix: z.string().nullable(),
    enforced: z.boolean().openapi({ description: "Counts toward compliance (the policy is in enforce mode)" }),
    grace_until: z.string().nullable().openapi({ description: "Failing, but not counted until then" }),
    updated_at: z.string(),
  })
  .openapi("DeviceCheck");

const DeviceDetail = DeviceSummary.extend({
  os_build: z.string(),
  arch: z.string(),
  agent_version: z.string(),
  last_ip: z.string(),
  compliance_changed_at: z.string().nullable(),
  checks: z.array(DeviceCheck),
  mdm: z
    .array(
      z.object({
        source: z.string(),
        connection: z.string(),
        managed: z.boolean(),
        compliant: z.boolean().nullable(),
        detail: z.string(),
        encrypted: z.boolean().nullable(),
        last_contact_at: z.string().nullable(),
      }),
    )
    .openapi({ description: "What each connected MDM (Intune, Jamf) reports about this device" }),
  inventory: z.record(z.string(), z.unknown()),
}).openapi("DeviceDetail");

type Row = Awaited<ReturnType<ReturnType<typeof deviceQuery>["execute"]>>[number];

const deviceQuery = (tx: Tx) =>
  tx
    .selectFrom("devices")
    .leftJoin("users", "users.id", "devices.primary_user_id")
    .selectAll("devices")
    .select(["users.email as user_email", "users.given_name as user_given", "users.family_name as user_family"])
    .select((eb) =>
      eb
        .selectFrom("device_checks")
        .whereRef("device_checks.device_id", "=", "devices.id")
        .where("device_checks.status", "=", "fail")
        .select(sql<string[]>`coalesce(array_agg(check_key ORDER BY check_key), '{}')`.as("f"))
        .as("failing_checks"),
    )
    .where("devices.status", "=", "active");

function toSummary(d: Row): z.infer<typeof DeviceSummary> {
  return {
    id: d.id,
    hostname: d.hostname,
    platform: d.platform,
    os_name: d.os_name,
    os_version: d.os_version,
    model: d.model,
    serial: d.serial,
    compliance: d.compliance,
    failing_checks: d.failing_checks ?? [],
    compliance_grace_until: isoOrNull(d.compliance_grace_until),
    online: !!d.last_seen_at && Date.now() - d.last_seen_at.getTime() < ONLINE_WINDOW_MS,
    last_seen_at: isoOrNull(d.last_seen_at),
    primary_user: d.primary_user_id
      ? { id: d.primary_user_id, email: d.user_email ?? "", display_name: `${d.user_given ?? ""} ${d.user_family ?? ""}`.trim() || (d.user_email ?? "") }
      : null,
    enrolled_at: iso(d.enrolled_at),
  };
}

async function detail(tx: Tx, id: string): Promise<z.infer<typeof DeviceDetail>> {
  const d = await deviceQuery(tx).where("devices.id", "=", id).executeTakeFirst();
  if (!d) throw notFound("Device");
  const checks = await tx.selectFrom("device_checks").selectAll().where("device_id", "=", id).execute();
  const order = (k: string) => CHECK_KEYS.indexOf(k as CheckKey);
  return {
    ...toSummary(d),
    os_build: d.os_build,
    arch: d.arch,
    agent_version: d.agent_version,
    last_ip: d.last_ip,
    compliance_changed_at: isoOrNull(d.compliance_changed_at),
    inventory: d.inventory as Record<string, unknown>,
    mdm: await mdmForDevice(tx, { id, serial: d.serial }),
    checks: checks
      .sort((a, b) => order(a.check_key) - order(b.check_key))
      .map((ch) => {
        const key = ch.check_key as CheckKey;
        return {
          key,
          title: CHECK_INFO[key].title,
          why: CHECK_INFO[key].why,
          status: ch.status,
          detail: ch.detail,
          fix: ch.status === "fail" || ch.status === "unknown" ? fixFor(key, d.platform as DevicePlatform) : null,
          enforced: ch.enforced,
          grace_until: isoOrNull(ch.grace_until),
          updated_at: iso(ch.updated_at),
        };
      }),
  };
}

// ---- Enrollment tokens -----------------------------------------------------------------

const EnrollmentToken = z
  .object({
    id: Id,
    name: z.string(),
    uses: z.number().int(),
    max_uses: z.number().int().nullable(),
    expires_at: z.string(),
    revoked: z.boolean(),
    assigned_user: z.string().nullable(),
    created_at: z.string(),
  })
  .openapi("EnrollmentToken");

const Install = z
  .object({
    token: z.string().openapi({ description: "Shown once" }),
    server: z.string(),
    commands: z.object({ macos: z.string(), linux: z.string(), windows: z.string() }),
  })
  .openapi("EnrollmentInstructions");

async function issueToken(
  tx: Tx,
  deps: Deps,
  a: { orgId: string; createdBy: string; name: string; days: number; maxUses: number | null; assignUserId: string | null },
) {
  const token = `nxe_${randomBytes(24).toString("base64url")}`;
  const id = newId();
  await tx
    .insertInto("device_enrollment_tokens")
    .values({
      id,
      org_id: a.orgId,
      name: a.name,
      token_hash: hashToken(token),
      assign_user_id: a.assignUserId,
      created_by: a.createdBy,
      max_uses: a.maxUses,
      expires_at: new Date(Date.now() + a.days * 86_400_000),
    })
    .execute();
  const server = deps.cfg.apiPublicUrl;
  const args = `enroll --server ${server} --token ${token}`;
  return {
    id,
    install: {
      token,
      server,
      commands: { macos: `sudo nexus-agent ${args}`, linux: `sudo nexus-agent ${args}`, windows: `nexus-agent.exe ${args}` },
    },
  };
}

export function registerDeviceRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/devices",
      tags: ["Devices"],
      summary: "List managed devices",
      security: bearer,
      request: {
        query: Cursor.extend({
          q: z.string().trim().max(200).optional().openapi({ description: "Hostname, serial or user email" }),
          platform: Platform.optional(),
          compliance: ComplianceEnum.optional(),
          user_id: Id.optional(),
        }),
      },
      responses: { 200: json(page(DeviceSummary, "DevicePage")), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const q = c.req.valid("query");
      const after = decodeCursor(q.cursor);
      const scope = scopeGroups(p, "devices:read");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) => {
        let query = deviceQuery(tx).orderBy("devices.id", "desc").limit(q.limit + 1);
        if (scope) query = query.where((eb) => eb.exists(eb.selectFrom("group_members").whereRef("group_members.user_id", "=", "devices.primary_user_id").where("group_members.group_id", "in", scope)));
        if (after) query = query.where("devices.id", "<", after);
        if (q.platform) query = query.where("devices.platform", "=", q.platform);
        if (q.compliance) query = query.where("devices.compliance", "=", q.compliance);
        if (q.user_id) query = query.where("devices.primary_user_id", "=", q.user_id);
        if (q.q) {
          const like = `%${q.q.replace(/[%_\\]/g, "\\$&")}%`;
          query = query.where((eb) => eb.or([eb("devices.hostname", "ilike", like), eb("devices.serial", "ilike", like), eb("users.email", "ilike", like)]));
        }
        return query.execute();
      });
      const pg = pageOf(rows, q.limit);
      return c.json({ data: pg.data.map(toSummary), next_cursor: pg.next_cursor }, 200);
    },
  );

  // Static paths first: /v1/devices/{id} would otherwise match "enrollment-tokens".
  // ---- Enrollment ---------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/devices/enrollment-tokens",
      tags: ["Devices"],
      summary: "Enrollment tokens",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(EnrollmentToken) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx
          .selectFrom("device_enrollment_tokens")
          .leftJoin("users", "users.id", "device_enrollment_tokens.assign_user_id")
          .selectAll("device_enrollment_tokens")
          .select("users.email")
          .where("device_enrollment_tokens.assign_user_id", "is", null) // personal tokens aren't admin-managed
          .orderBy("device_enrollment_tokens.created_at", "desc")
          .limit(100)
          .execute(),
      );
      return c.json(
        {
          data: rows.map((t) => ({
            id: t.id,
            name: t.name,
            uses: t.uses,
            max_uses: t.max_uses,
            expires_at: iso(t.expires_at),
            revoked: !!t.revoked_at || t.expires_at < new Date(),
            assigned_user: t.email,
            created_at: iso(t.created_at),
          })),
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/devices/enrollment-tokens",
      tags: ["Devices"],
      summary: "Create an enrollment token (for MDM or manual installs)",
      security: bearer,
      request: body(
        z.object({
          name: z.string().trim().min(1).max(100),
          expires_in_days: z.number().int().min(1).max(365).default(30),
          max_uses: z.number().int().min(1).max(100_000).nullable().default(null),
        }),
      ),
      responses: { 201: json(Install, "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const t = await issueToken(tx, deps, { orgId: p.orgId, createdBy: p.userId, name: input.name, days: input.expires_in_days, maxUses: input.max_uses, assignUserId: null });
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "device.enrollment_token_created",
          target: { type: "enrollment_token", id: t.id, display: input.name },
          details: { expires_in_days: input.expires_in_days, max_uses: input.max_uses },
        });
        return t.install;
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/devices/{id}",
      tags: ["Devices"],
      summary: "Device details: inventory and each policy check with the reason and fix",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(DeviceDetail), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const id = c.req.valid("param").id;
      return c.json(await c.get("deps").db.tenant(p.orgId, async (tx) => (await assertDeviceInScope(tx, p, "devices:read", id), detail(tx, id))), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/devices/{id}",
      tags: ["Devices"],
      summary: "Assign the device's primary user",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ primary_user_id: Id.nullable() })) },
      responses: { 200: json(DeviceDetail), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      const { primary_user_id } = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const before = await detail(tx, id);
        if (primary_user_id && !(await tx.selectFrom("users").select("id").where("id", "=", primary_user_id).executeTakeFirst())) throw notFound("User");
        await tx.updateTable("devices").set({ primary_user_id, updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "device.user_assigned",
          target: { type: "device", id, display: before.hostname },
          details: { from: before.primary_user?.id ?? null, to: primary_user_id },
        });
        return detail(tx, id);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/devices/{id}",
      tags: ["Devices"],
      summary: "Remove a device: its key is no longer accepted and the agent stops reporting",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 204: { description: "Removed" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const d = await detail(tx, id);
        await tx.updateTable("devices").set({ status: "removed", updated_at: new Date() }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.removed", target: { type: "device", id, display: d.hostname } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/devices/enrollment-tokens/{id}",
      tags: ["Devices"],
      summary: "Revoke an enrollment token (enrolled devices are not affected)",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 204: { description: "Revoked" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const t = await tx.updateTable("device_enrollment_tokens").set({ revoked_at: new Date() }).where("id", "=", id).where("revoked_at", "is", null).returning("name").executeTakeFirst();
        if (!t) throw notFound("Enrollment token");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.enrollment_token_revoked", target: { type: "enrollment_token", id, display: t.name } });
      });
      return c.body(null, 204);
    },
  );

  // ---- My devices (every signed-in user, SPEC PORT-03) ----------------------------------

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/devices",
      tags: ["Me"],
      summary: "My devices, with what to fix",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(DeviceDetail) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const ids = await tx.selectFrom("devices").select("id").where("primary_user_id", "=", p.userId).where("status", "=", "active").orderBy("id", "desc").execute();
        return Promise.all(ids.map((d) => detail(tx, d.id)));
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/devices/enrollment-token",
      tags: ["Me"],
      summary: "Get a one-time token to enroll one of my own devices",
      description: "Valid for 24 hours and one device; the device is assigned to me automatically.",
      security: bearer,
      responses: { 201: json(Install, "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const t = await issueToken(tx, deps, { orgId: p.orgId, createdBy: p.userId, name: `Personal (${p.email})`, days: 1, maxUses: 1, assignUserId: p.userId });
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.enrollment_token_created", target: { type: "enrollment_token", id: t.id, display: "Personal" }, details: { personal: true } });
        return t.install;
      });
      return c.json(out, 201);
    },
  );

  // ---- Device policies (SPEC DPOL-01..03) ----------------------------------------------

  const PolicySchema = z
    .object({
      key: z.enum(CHECK_KEYS),
      title: z.string(),
      why: z.string(),
      enabled: z.boolean(),
      params: z.record(z.string(), z.unknown()),
      mode: z.enum(["audit", "enforce"]).openapi({ description: "enforce: counts toward compliance (and so conditional access); audit: reported only" }),
      grace_hours: z.number().int().openapi({ description: "How long an enforced check may fail before it counts (0 = at once)" }),
    })
    .openapi("DevicePolicy");

  const policiesOut = async (tx: Tx) =>
    (await getPolicies(tx)).map((p) => ({ key: p.key, title: CHECK_INFO[p.key].title, why: CHECK_INFO[p.key].why, enabled: p.enabled, params: p.params, mode: p.mode, grace_hours: p.grace_hours }));

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/device-policies",
      tags: ["Devices"],
      summary: "Device compliance policies",
      description: "Enforced policies decide whether a device is compliant (after an optional grace period); audited ones are only reported. Blocking sign-in from non-compliant devices is configured in conditional access.",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(PolicySchema) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, policiesOut) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/device-policies/{key}",
      tags: ["Devices"],
      summary: "Turn a policy on/off or change its settings; all devices are re-evaluated immediately",
      security: bearer,
      request: {
        params: z.object({ key: z.enum(CHECK_KEYS) }),
        ...body(
          z.object({
            enabled: z.boolean(),
            params: z.record(z.string(), z.unknown()).default({}),
            mode: z.enum(["audit", "enforce"]).optional().openapi({ description: "Unchanged when omitted" }),
            grace_hours: z.number().int().min(0).max(720).optional().openapi({ description: "Unchanged when omitted" }),
          }),
        ),
      },
      responses: { 200: json(z.object({ data: z.array(PolicySchema), reevaluated: z.object({ devices: z.number().int(), changed: z.number().int() }) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { key } = c.req.valid("param");
      const input = c.req.valid("json");
      const params = PolicyParams[key].safeParse(input.params);
      if (!params.success) throw badRequest("invalid_params", params.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
      const meta = c.get("meta");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const before = (await getPolicies(tx)).find((x) => x.key === key)!;
        const row = { enabled: input.enabled, params: JSON.stringify(params.data), mode: input.mode ?? before.mode, grace_hours: input.grace_hours ?? before.grace_hours, updated_at: new Date() };
        await tx
          .insertInto("device_policies")
          .values({ org_id: p.orgId, check_key: key, ...row })
          .onConflict((oc) => oc.columns(["org_id", "check_key"]).doUpdateSet(row))
          .execute();
        await audit(tx, p.orgId, { principal: p, meta }, {
          type: "device.policy_updated",
          target: { type: "device_policy", id: null, display: CHECK_INFO[key].title },
          details: {
            key,
            from: { enabled: before.enabled, params: before.params, mode: before.mode, grace_hours: before.grace_hours },
            to: { enabled: input.enabled, params: params.data, mode: row.mode, grace_hours: row.grace_hours },
          },
        });
        const reevaluated = await reevaluateAll(tx, { meta });
        return { data: await policiesOut(tx), reevaluated };
      });
      return c.json(out, 200);
    },
  );
}

import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import type { JobRunner } from "../platform/jobs.js";
import { bearer, body, Id, isoOrNull, json, problemResponses } from "../schemas.js";
import { Amapi, AmapiError, buildPolicy, DEFAULT_POLICY, readServiceAccount, type AmapiDevice, type PolicySettings } from "./amapi.js";

/**
 * Android Enterprise (docs/ANDROID.md): Nexus as the organization's EMM through Google's Android
 * Management API. The organization brings its own Google Cloud project and service account;
 * Nexus creates its Android enterprise, keeps one policy, hands out enrollment tokens (a QR code
 * for company phones, a link for work profiles on personal ones), mirrors the devices Google
 * reports, and sends commands. Nothing on the phone talks to Nexus directly: Google's Android
 * Device Policy app does, and reports to Google.
 */

const POLICY_ID = "nexus";
const aad = (orgId: string) => `android_sa:${orgId}`;

const Settings = z
  .object({
    password_min_length: z.number().int().min(0).max(16).openapi({ description: "0: no passcode required" }),
    lock_after_minutes: z.number().int().min(1).max(60),
    block_unknown_sources: z.boolean().openapi({ description: "No apps from outside Google Play" }),
    disable_camera: z.boolean(),
    apps: z
      .array(z.object({ package: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/, "An Android package name, like com.slack"), install: z.enum(["force", "available", "blocked"]) }))
      .max(200),
  })
  .openapi("AndroidPolicySettings");

async function settingsRow(tx: Tx) {
  return tx.selectFrom("android_settings").selectAll().executeTakeFirst();
}

function client(deps: Deps, orgId: string, row: { service_account: Buffer | null }) {
  if (!row.service_account) throw conflict("not_configured", "Add your Google Cloud service account first");
  const sa = readServiceAccount(deps.sealer.open(row.service_account, aad(orgId)).toString(), deps.cfg.googleTokenUrl);
  return new Amapi(deps.cfg.androidApiBase, deps.cfg.googleTokenUrl, sa);
}

const google = async <T>(fn: () => Promise<T>) => {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof AmapiError) throw new ApiError(502, "google_error", e.message);
    throw e;
  }
};

const policyOf = (row: { policy: unknown } | undefined): PolicySettings => ({ ...DEFAULT_POLICY, ...((row?.policy ?? {}) as Partial<PolicySettings>) });

/** Brings Nexus's copy of the devices up to date with what Google reports. */
export async function syncAndroid(tx: Tx, deps: Deps, orgId: string) {
  const row = await settingsRow(tx);
  if (!row?.enterprise_name) throw conflict("not_connected", "Connect an Android enterprise first");
  try {
    const devices = await client(deps, orgId, row).devices(row.enterprise_name);
    const users = new Set((await tx.selectFrom("users").select("id").execute()).map((u) => u.id));
    for (const d of devices) await upsert(tx, orgId, d, users);
    // Devices Google no longer lists (deleted there) are removed here too.
    const names = devices.map((d) => d.name);
    let del = tx.deleteFrom("android_devices");
    if (names.length) del = del.where("name", "not in", names);
    await del.execute();
    await tx.updateTable("android_settings").set({ last_sync_at: new Date(), last_error: "" }).execute();
    return devices.length;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    await tx.updateTable("android_settings").set({ last_error: msg.slice(0, 500) }).execute();
    throw e instanceof AmapiError ? new ApiError(502, "google_error", e.message) : e;
  }
}

async function upsert(tx: Tx, orgId: string, d: AmapiDevice, users: Set<string>) {
  // The enrollment token carried whose device it is, when Nexus made it for someone.
  let owner: string | null = null;
  try {
    const data = JSON.parse(d.enrollmentTokenData ?? "{}") as { user_id?: string };
    if (data.user_id && users.has(data.user_id)) owner = data.user_id;
  } catch {
    /* not ours */
  }
  const fields = {
    serial: d.hardwareInfo?.serialNumber ?? "",
    brand: d.hardwareInfo?.brand ?? d.hardwareInfo?.manufacturer ?? "",
    model: d.hardwareInfo?.model ?? "",
    android_version: d.softwareInfo?.androidVersion ?? "",
    security_patch: d.softwareInfo?.securityPatchLevel ?? "",
    management_mode: d.managementMode ?? "",
    ownership: d.ownership ?? "",
    state: d.appliedState ?? d.state ?? "",
    policy_compliant: typeof d.policyCompliant === "boolean" ? d.policyCompliant : null,
    non_compliance: JSON.stringify((d.nonComplianceDetails ?? []).slice(0, 50)),
    enrolled_at: d.enrollmentTime ? new Date(d.enrollmentTime) : null,
    last_status_at: d.lastStatusReportTime ? new Date(d.lastStatusReportTime) : null,
    updated_at: new Date(),
  };
  await tx
    .insertInto("android_devices")
    .values({ id: newId(), org_id: orgId, name: d.name, ...fields, assigned_user_id: owner })
    .onConflict((oc) => oc.columns(["org_id", "name"]).doUpdateSet({ ...fields, assigned_user_id: sql`coalesce(android_devices.assigned_user_id, excluded.assigned_user_id)` }))
    .execute();
}

async function applyPolicy(tx: Tx, deps: Deps, orgId: string, s: PolicySettings) {
  const row = await settingsRow(tx);
  if (!row?.enterprise_name) return;
  await google(() => client(deps, orgId, row).patchPolicy(`${row.enterprise_name}/policies/${POLICY_ID}`, buildPolicy(s)));
  await tx.updateTable("android_settings").set({ policy_applied_at: new Date() }).execute();
}

const DeviceOut = z
  .object({
    id: Id,
    serial: z.string(),
    brand: z.string(),
    model: z.string(),
    android_version: z.string(),
    security_patch: z.string(),
    kind: z.enum(["company", "work_profile", "unknown"]).openapi({ description: "company: fully managed (DEVICE_OWNER). work_profile: a personal phone with a work profile" }),
    state: z.string(),
    policy_compliant: z.boolean().nullable(),
    non_compliance: z.array(z.object({ setting: z.string(), reason: z.string() })),
    assigned_user: z.object({ id: Id, email: z.string() }).nullable(),
    enrolled_at: z.string().nullable(),
    last_status_at: z.string().nullable(),
  })
  .openapi("AndroidDevice");

export function registerAndroidRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/android",
      tags: ["Android"],
      summary: "Whether Android Enterprise is connected, and its policy",
      security: bearer,
      responses: {
        200: json(
          z.object({
            service_account: z.string().nullable().openapi({ description: "The service account's email, once added" }),
            project_id: z.string(),
            enterprise: z.object({ name: z.string(), display_name: z.string() }).nullable(),
            policy: Settings,
            policy_applied_at: z.string().nullable(),
            devices: z.number().int(),
            last_sync_at: z.string().nullable(),
            last_error: z.string(),
            callback_url: z.string().openapi({ description: "Where Google sends admins back after creating the enterprise" }),
          }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const r = await settingsRow(tx);
        const n = await tx.selectFrom("android_devices").select((eb) => eb.fn.countAll<number>().as("n")).executeTakeFirstOrThrow();
        return {
          service_account: r?.service_account ? r.client_email : null,
          project_id: r?.project_id ?? "",
          enterprise: r?.enterprise_name ? { name: r.enterprise_name, display_name: r.enterprise_display } : null,
          policy: policyOf(r),
          policy_applied_at: isoOrNull(r?.policy_applied_at ?? null),
          devices: Number(n.n),
          last_sync_at: isoOrNull(r?.last_sync_at ?? null),
          last_error: r?.last_error ?? "",
          callback_url: `${deps.cfg.publicUrl}/android/connected`,
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/android/service-account",
      tags: ["Android"],
      summary: "Add the Google Cloud service account Nexus manages Android with",
      description: "A JSON key for a service account with the Android Management User role, in a project with the Android Management API enabled. Stored sealed. Owners and admins (`org:manage`) only, with a recent MFA.",
      security: bearer,
      request: body(z.object({ project_id: z.string().trim().min(3).max(100), key_json: z.string().min(100).max(20_000) })),
      responses: { 200: json(z.object({ service_account: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      let sa;
      try {
        sa = readServiceAccount(input.key_json, deps.cfg.googleTokenUrl);
      } catch (e) {
        throw badRequest("invalid_key", (e as Error).message);
      }
      await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const row = { project_id: input.project_id, service_account: deps.sealer.seal(Buffer.from(input.key_json), aad(p.orgId)), client_email: sa.client_email, updated_at: new Date() };
        await tx.insertInto("android_settings").values({ org_id: p.orgId, ...row }).onConflict((oc) => oc.column("org_id").doUpdateSet(row)).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "android.service_account_set", details: { project_id: input.project_id, service_account: sa.client_email } });
      });
      return c.json({ service_account: sa.client_email }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/android/signup",
      tags: ["Android"],
      summary: "Start creating the organization's Android enterprise (returns Google's sign-up page)",
      security: bearer,
      responses: { 200: json(z.object({ url: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const row = await settingsRow(tx);
        if (!row) throw conflict("not_configured", "Add your Google Cloud service account first");
        const r = await google(() => client(deps, p.orgId, row).signupUrl(row.project_id, `${deps.cfg.publicUrl}/android/connected`));
        await tx.updateTable("android_settings").set({ signup_url_name: r.name }).execute();
        return { url: r.url };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/android/enterprise",
      tags: ["Android"],
      summary: "Finish creating the Android enterprise, with the token Google sent back",
      security: bearer,
      request: body(z.object({ enterprise_token: z.string().min(10).max(500) })),
      responses: { 200: json(z.object({ name: z.string(), display_name: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const { enterprise_token } = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const row = await settingsRow(tx);
        if (!row?.signup_url_name) throw conflict("no_signup", "Start from Connect to Google");
        if (row.enterprise_name) throw conflict("already_connected", "An Android enterprise is already connected");
        const org = await tx.selectFrom("organizations").select("name").executeTakeFirstOrThrow();
        const e = await google(() => client(deps, p.orgId, row).createEnterprise(row.project_id, row.signup_url_name, enterprise_token, org.name));
        await tx.updateTable("android_settings").set({ enterprise_name: e.name, enterprise_display: e.enterpriseDisplayName ?? org.name, signup_url_name: "" }).execute();
        await applyPolicy(tx, deps, p.orgId, policyOf(row));
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "android.enterprise_connected", details: { enterprise: e.name } });
        return { name: e.name, display_name: e.enterpriseDisplayName ?? org.name };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/android/policy",
      tags: ["Android"],
      summary: "Set the Android policy (passcode, screen lock, apps, camera)",
      description: "Applied to every enrolled device through Google. Needs `devices:enforce` and a recent MFA.",
      security: bearer,
      request: body(Settings),
      responses: { 200: json(Settings), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const row = await settingsRow(tx);
        if (!row) throw conflict("not_configured", "Add your Google Cloud service account first");
        await applyPolicy(tx, deps, p.orgId, input);
        await tx.updateTable("android_settings").set({ policy: JSON.stringify(input), updated_at: new Date() }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "android.policy_updated", details: { from: policyOf(row), to: input } });
      });
      return c.json(input, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/android/enrollment-tokens",
      tags: ["Android"],
      summary: "Make an enrollment token: a QR code for company phones, a link for work profiles",
      description:
        "Company phones: factory reset, tap the welcome screen six times, and scan the QR code. Personal phones: open the link to add a work profile. Naming a person makes the device theirs when it enrolls.",
      security: bearer,
      request: body(z.object({ kind: z.enum(["company", "work_profile"]), user_id: Id.nullable().default(null), days: z.number().int().min(1).max(90).default(7) })),
      responses: { 201: json(z.object({ value: z.string(), qr_code: z.string(), enroll_url: z.string(), expires_at: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const row = await settingsRow(tx);
        if (!row?.enterprise_name) throw conflict("not_connected", "Connect an Android enterprise first");
        if (input.user_id && !(await tx.selectFrom("users").select("id").where("id", "=", input.user_id).executeTakeFirst())) throw badRequest("unknown_user", "No such person");
        const t = await google(() =>
          client(deps, p.orgId, row).enrollmentToken(row.enterprise_name, {
            policyName: `${row.enterprise_name}/policies/${POLICY_ID}`,
            duration: `${input.days * 86_400}s`,
            allowPersonalUsage: input.kind === "work_profile" ? "PERSONAL_USAGE_ALLOWED" : "PERSONAL_USAGE_DISALLOWED",
            additionalData: JSON.stringify({ user_id: input.user_id }),
          }),
        );
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "android.enrollment_token_created", details: { kind: input.kind, user_id: input.user_id, days: input.days } });
        return { value: t.value, qr_code: t.qrCode, enroll_url: `https://enterprise.google.com/android/enroll?et=${encodeURIComponent(t.value)}`, expires_at: t.expirationTimestamp };
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/android/sync", tags: ["Android"], summary: "Fetch the devices Google reports now", security: bearer, responses: { 200: json(z.object({ devices: z.number().int() })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const deps = c.get("deps");
      const n = await deps.db.tenant(p.orgId, (tx) => syncAndroid(tx, deps, p.orgId));
      return c.json({ devices: n }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/android/devices", tags: ["Android"], summary: "Enrolled Android devices", security: bearer, responses: { 200: json(z.object({ data: z.array(DeviceOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const rows = await tx.selectFrom("android_devices").leftJoin("users", "users.id", "android_devices.assigned_user_id").selectAll("android_devices").select("users.email").orderBy("android_devices.model").execute();
        return rows.map((d) => ({
          id: d.id,
          serial: d.serial,
          brand: d.brand,
          model: d.model,
          android_version: d.android_version,
          security_patch: d.security_patch,
          kind: d.management_mode === "DEVICE_OWNER" ? ("company" as const) : d.management_mode === "PROFILE_OWNER" ? ("work_profile" as const) : ("unknown" as const),
          state: d.state,
          policy_compliant: d.policy_compliant,
          non_compliance: (d.non_compliance as { settingName?: string; nonComplianceReason?: string }[]).map((n) => ({ setting: n.settingName ?? "", reason: n.nonComplianceReason ?? "" })),
          assigned_user: d.assigned_user_id && d.email ? { id: d.assigned_user_id, email: d.email } : null,
          enrolled_at: isoOrNull(d.enrolled_at),
          last_status_at: isoOrNull(d.last_status_at),
        }));
      });
      return c.json({ data: out }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/android/devices/{id}/commands",
      tags: ["Android"],
      summary: "Lock, reboot, or turn Lost Mode on or off",
      description: "Reboot and Lost Mode are for company phones (fully managed). Needs `devices:actions` and a recent MFA.",
      security: bearer,
      request: {
        params: z.object({ id: Id }),
        ...body(z.object({ command: z.enum(["lock", "reboot", "start_lost_mode", "stop_lost_mode"]), reason: z.string().trim().min(3).max(500), message: z.string().trim().max(200).optional(), phone: z.string().trim().max(40).optional() })),
      },
      responses: { 202: json(z.object({ operation: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:actions");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const d = await tx.selectFrom("android_devices").select(["name", "model", "serial", "management_mode"]).where("id", "=", id).executeTakeFirst();
        if (!d) throw notFound("Device");
        if (input.command !== "lock" && d.management_mode !== "DEVICE_OWNER") throw badRequest("unsupported", "Only company phones (fully managed) can be rebooted or put in Lost Mode; a work profile can be locked");
        const row = (await settingsRow(tx))!;
        const cmd =
          input.command === "start_lost_mode"
            ? { type: "START_LOST_MODE", startLostModeParams: { lostMessage: { defaultMessage: input.message || "This phone is lost. Please call the number shown." }, ...(input.phone ? { lostPhoneNumber: { defaultMessage: input.phone } } : {}) } }
            : { type: input.command.toUpperCase() };
        const op = await google(() => client(deps, p.orgId, row).issueCommand(d.name, cmd));
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "android.command_sent", target: { type: "android_device", id, display: `${d.model} ${d.serial}`.trim() }, details: { command: input.command, reason: input.reason } });
        return { operation: op.name ?? "" };
      });
      return c.json(out, 202);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/android/devices/{id}",
      tags: ["Android"],
      summary: "Remove a device: erases a company phone, or removes the work profile from a personal one",
      description: "Needs `devices:wipe`, a recent MFA, and the serial number typed to confirm.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ reason: z.string().trim().min(3).max(200), confirm: z.string().max(100) })) },
      responses: { 204: { description: "Removed" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:wipe");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const d = await tx.selectFrom("android_devices").select(["name", "model", "serial", "management_mode"]).where("id", "=", id).executeTakeFirst();
        if (!d) throw notFound("Device");
        if (input.confirm.trim() !== d.serial) throw badRequest("confirm_mismatch", `Type the serial number (${d.serial}) to confirm`);
        const row = (await settingsRow(tx))!;
        await google(() => client(deps, p.orgId, row).deleteDevice(d.name, input.reason));
        await tx.deleteFrom("android_devices").where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "android.device_removed",
          target: { type: "android_device", id, display: `${d.model} ${d.serial}`.trim() },
          details: { reason: input.reason, effect: d.management_mode === "DEVICE_OWNER" ? "factory reset" : "work profile removed" },
        });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({ method: "put", path: "/v1/android/devices/{id}/user", tags: ["Android"], summary: "Say whose phone this is", security: bearer, request: { params: z.object({ id: Id }), ...body(z.object({ user_id: Id.nullable() })) }, responses: { 204: { description: "Assigned" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      const { user_id } = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const d = await tx.selectFrom("android_devices").select(["model", "serial"]).where("id", "=", id).executeTakeFirst();
        if (!d) throw notFound("Device");
        if (user_id && !(await tx.selectFrom("users").select("id").where("id", "=", user_id).executeTakeFirst())) throw badRequest("unknown_user", "No such person");
        await tx.updateTable("android_devices").set({ assigned_user_id: user_id }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "android.device_assigned", target: { type: "android_device", id, display: `${d.model} ${d.serial}`.trim() }, details: { user_id } });
      });
      return c.body(null, 204);
    },
  );
}

/** Hourly: every connected organization's devices. */
export function scheduleAndroidSync(jobs: JobRunner, deps: Deps) {
  jobs.every("android.sync", 60 * 60_000, async () => {
    const orgs = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_android_orgs()`.execute(tx)).rows);
    for (const o of orgs) await deps.db.tenant(o.org_id, (tx) => syncAndroid(tx, deps, o.org_id)).catch(() => undefined); // recorded as last_error
  });
}

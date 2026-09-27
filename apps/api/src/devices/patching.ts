import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import type { JobRunner } from "../platform/jobs.js";
import { badRequest, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";

/**
 * OS patching (like JumpCloud's patch policies). The agent checks for OS updates every few hours
 * (softwareupdate, Windows Update, apt or dnf) and reports them with its inventory. Admins install
 * them on demand, or a patch policy does it once security updates have waited past its deadline,
 * inside a maintenance window. Installs are 'updates' commands signed with the org's key; the
 * agent restarts afterwards only when the policy allows and the OS asks for it.
 */

/** What the agent reports under inventory.updates (validated on its own, like the AI report). */
export const UpdatesReport = z.object({
  checked_at: z.iso.datetime({ offset: true }),
  available: z
    .array(
      z.object({
        name: z.string().max(300),
        version: z.string().max(200).optional(),
        security: z.boolean(),
        restart: z.boolean(),
        upgrade: z.boolean().optional().openapi({ description: "A major OS upgrade (e.g. the next macOS): shown, but never installed by patching" }),
        third_party: z.boolean().optional().openapi({ description: "An app, not the OS (Chrome, Zoom…)" }),
        app_id: z.string().max(200).optional().openapi({ description: "winget ID, or the macOS catalog ID" }),
        current: z.string().max(200).optional().openapi({ description: "The version installed now" }),
      }),
    )
    .max(2000),
  error: z.string().max(1000).optional(),
  third_party_error: z.string().max(1000).optional(),
});
export type UpdatesReport = z.infer<typeof UpdatesReport>;

/** An install's outcome, as the agent returns it. */
export const UpdatesResult = z.object({ summary: z.string().max(2000), restarted: z.boolean() });

/**
 * Keeps the device's update counts, and since when some have been pending: the clock starts when
 * a device goes from none to some and stops only when none are left. A failed check changes nothing
 * but the error, so a flaky package mirror can't reset the clock.
 */
export async function recordUpdates(tx: Tx, deviceId: string, r: UpdatesReport) {
  const checked = new Date(r.checked_at);
  const apps = r.available.filter((u) => u.third_party).length;
  // A failed app check keeps the app counts as they were, like a failed OS check keeps OS counts.
  const appFields = r.third_party_error ? {} : { third_party_pending: apps, third_party_since: apps ? sql<Date>`COALESCE(third_party_since, now())` : null };
  if (r.error) {
    await tx.updateTable("devices").set({ updates_checked_at: checked, updates_error: r.error.slice(0, 500), ...appFields }).where("id", "=", deviceId).execute();
    return;
  }
  const updates = r.available.filter((u) => !u.upgrade && !u.third_party);
  const all = updates.length;
  const security = updates.filter((u) => u.security).length;
  await tx
    .updateTable("devices")
    .set({
      updates_checked_at: checked,
      updates_error: null,
      updates_pending: all,
      security_updates_pending: security,
      updates_pending_since: all ? sql<Date>`COALESCE(updates_pending_since, now())` : null,
      security_updates_since: security ? sql<Date>`COALESCE(security_updates_since, now())` : null,
      ...appFields,
    })
    .where("id", "=", deviceId)
    .execute();
}

const Scope = z.enum(["security", "all"]);
const Restart = z.enum(["never", "if_needed"]);
const MAX_TARGETS = 1000;
const MANUAL_TTL_MS = 24 * 3600_000; // offline devices pick it up within a day
const AUTO_TTL_MS = 3600_000; // queued inside the window for an online device: it runs now or not at all

const PatchPolicy = z
  .object({
    enabled: z.boolean(),
    scope: Scope.openapi({ description: "Install security updates only, or everything pending" }),
    deadline_days: z.number().int().min(0).max(90).openapi({ description: "Days an update may wait before the policy installs it (0: as soon as it's seen)" }),
    restart: Restart.openapi({ description: "Restart after installing when the OS asks for it (the signed-in person gets a warning first)" }),
    window_start: z.number().int().min(0).max(23).openapi({ description: "Maintenance window start hour (local time in `timezone`)" }),
    window_end: z.number().int().min(0).max(23).openapi({ description: "Maintenance window end hour; may wrap past midnight; equal to start means any time" }),
    timezone: z.string().min(1).max(64),
    third_party: z.boolean().default(false).openapi({ description: "Also keep third-party apps (Chrome, Zoom…) up to date, on the same deadline and window" }),
  })
  .openapi("PatchPolicy");
type PatchPolicy = z.infer<typeof PatchPolicy>;
const DEFAULT_POLICY: PatchPolicy = { enabled: false, scope: "security", deadline_days: 3, restart: "never", window_start: 1, window_end: 5, timezone: "UTC", third_party: false };

async function getPolicy(tx: Tx): Promise<PatchPolicy & { updated_at: string | null }> {
  const r = await tx.selectFrom("patch_policies").selectAll().executeTakeFirst();
  if (!r) return { ...DEFAULT_POLICY, updated_at: null };
  return { enabled: r.enabled, scope: r.scope, deadline_days: r.deadline_days, restart: r.restart, window_start: r.window_start, window_end: r.window_end, timezone: r.timezone, third_party: r.third_party, updated_at: iso(r.updated_at) };
}

/** Queues installs, skipping devices that already have one queued or running. Returns the devices queued. */
async function queueInstalls(tx: Tx, orgId: string, deviceIds: string[], o: { scope: "security" | "all" | "none"; restart: "never" | "if_needed"; apps?: boolean; reason: string; requestedBy: string | null; ttlMs: number }) {
  if (!deviceIds.length) return [];
  const busy = new Set(
    (await tx.selectFrom("device_commands").select("device_id").where("device_id", "in", deviceIds).where("action", "=", "updates").where("status", "in", ["queued", "sent"]).execute()).map((r) => r.device_id),
  );
  const ids = deviceIds.filter((id) => !busy.has(id));
  if (!ids.length) return [];
  const expires = new Date(Date.now() + o.ttlMs);
  await tx
    .insertInto("device_commands")
    .values(ids.map((device_id) => ({ id: newId(), org_id: orgId, device_id, action: "updates" as const, channel: "agent" as const, reason: o.reason, requested_by: o.requestedBy, expires_at: expires, args: JSON.stringify({ scope: o.scope, restart: o.restart, third_party: !!o.apps }), query_id: null })))
    .execute();
  return ids;
}

const SYSTEM_META = { ip: "", userAgent: "nexus-scheduler", requestId: "" };

/** One pass of every org's patch policy: installs on devices past the deadline, inside the window. */
export async function runPatchPolicies(deps: Deps) {
  const due = await deps.db.unscoped(
    async (tx) => (await sql<{ org_id: string; device_id: string; scope: "security" | "all"; restart: "never" | "if_needed"; os_due: boolean; apps_due: boolean }>`SELECT * FROM nexus_patch_due()`.execute(tx)).rows,
  );
  // One batch per org and per what's due (OS, apps, or both): each command says exactly what to do.
  const batches = new Map<string, typeof due>();
  for (const d of due) {
    const k = `${d.org_id}|${d.os_due}|${d.apps_due}`;
    batches.set(k, [...(batches.get(k) ?? []), d]);
  }
  let queued = 0;
  for (const rows of batches.values()) {
    const { org_id: orgId, scope, restart, os_due, apps_due } = rows[0]!;
    await deps.db.tenant(orgId, async (tx) => {
      const ids = await queueInstalls(tx, orgId, rows.map((r) => r.device_id), { scope: os_due ? scope : "none", restart, apps: apps_due, reason: "Patch policy", requestedBy: null, ttlMs: AUTO_TTL_MS });
      if (!ids.length) return;
      queued += ids.length;
      await audit(tx, orgId, { meta: SYSTEM_META }, {
        type: "device.updates_install",
        actor: { type: "system", id: null, display: "Patch policy" },
        target: { type: "organization", id: orgId },
        details: { automatic: true, scope: os_due ? scope : "none", apps: apps_due, restart, devices: ids.length, device_ids: ids.slice(0, 50) },
      });
    });
  }
  return { queued };
}

export function schedulePatching(jobs: JobRunner, deps: Deps) {
  jobs.every("devices.patching", 10 * 60_000, async () => {
    await runPatchPolicies(deps);
  });
}

const Target = z
  .object({ device_ids: z.array(Id).max(MAX_TARGETS).optional(), group_id: Id.optional(), all: z.literal(true).optional() })
  .refine((t) => [t.device_ids?.length ? 1 : 0, t.group_id ? 1 : 0, t.all ? 1 : 0].reduce((a, b) => a + b, 0) === 1, "Choose devices, a group, or all devices");

const Install = z.object({ status: z.string(), output: z.string(), automatic: z.boolean(), requested_by: z.string().nullable(), created_at: z.string(), finished_at: z.string().nullable() });

const FleetRow = z
  .object({
    device_id: Id,
    hostname: z.string(),
    platform: z.string(),
    os_version: z.string(),
    last_seen_at: z.string().nullable(),
    checked_at: z.string().nullable(),
    error: z.string().nullable(),
    pending: z.number().int(),
    security_pending: z.number().int(),
    pending_since: z.string().nullable(),
    security_since: z.string().nullable(),
    apps_pending: z.number().int().openapi({ description: "Third-party apps with a newer version" }),
    apps_since: z.string().nullable(),
    overdue: z.boolean().openapi({ description: "Past the patch policy's deadline (false while the policy is off)" }),
    last_install: Install.nullable(),
  })
  .openapi("DeviceUpdatesRow");

const installOf = (r: { status: string; output: string; requested_by: string | null; email?: string | null; created_at: Date; finished_at: Date | null }) => ({
  status: r.status,
  output: r.output,
  automatic: !r.requested_by,
  requested_by: r.email ?? null,
  created_at: iso(r.created_at),
  finished_at: isoOrNull(r.finished_at),
});

export function registerPatchingRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/patch-policy", tags: ["Devices"], summary: "The organization's patch policy", security: bearer, responses: { 200: json(PatchPolicy.extend({ updated_at: z.string().nullable() })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      return c.json(await c.get("deps").db.tenant(p.orgId, getPolicy), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/patch-policy",
      tags: ["Devices"],
      summary: "Change the patch policy",
      description: "Installs OS updates automatically, as signed commands, once they've been pending longer than `deadline_days`, on online devices inside the maintenance window. Needs `devices:updates` and a recent MFA.",
      security: bearer,
      request: body(PatchPolicy),
      responses: { 200: json(PatchPolicy.extend({ updated_at: z.string().nullable() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:updates");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const tz = await sql<{ ok: number }>`SELECT 1 AS ok FROM pg_timezone_names WHERE name = ${input.timezone}`.execute(tx);
        if (!tz.rows.length) throw badRequest("invalid_timezone", `Unknown time zone "${input.timezone}" (use an IANA name like Europe/Berlin)`);
        const before = await getPolicy(tx);
        const values = { ...input, updated_by: p.userId, updated_at: new Date() };
        await tx.insertInto("patch_policies").values({ org_id: p.orgId, ...values }).onConflict((oc) => oc.column("org_id").doUpdateSet(values)).execute();
        const { updated_at: _, ...prev } = before;
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.patch_policy_changed", target: { type: "organization", id: p.orgId }, details: { before: prev, after: input } });
        return getPolicy(tx);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/device-updates",
      tags: ["Devices"],
      summary: "Pending OS updates across the fleet",
      security: bearer,
      responses: {
        200: json(
          z.object({
            summary: z.object({ devices: z.number().int(), reporting: z.number().int(), up_to_date: z.number().int(), with_security: z.number().int(), apps_outdated: z.number().int(), overdue: z.number().int(), failing_checks: z.number().int() }),
            policy: PatchPolicy,
            data: z.array(FleetRow),
          }),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const policy = await getPolicy(tx);
        const devices = await tx
          .selectFrom("devices")
          .select(["id", "hostname", "platform", "os_version", "last_seen_at", "updates_checked_at", "updates_error", "updates_pending", "security_updates_pending", "updates_pending_since", "security_updates_since", "third_party_pending", "third_party_since"])
          .where("status", "=", "active")
          .orderBy("security_updates_pending", "desc")
          .orderBy("updates_pending", "desc")
          .orderBy("hostname")
          .limit(5000)
          .execute();
        const last = devices.length
          ? await tx
              .selectFrom("device_commands")
              .leftJoin("users", "users.id", "device_commands.requested_by")
              .distinctOn("device_commands.device_id")
              .select(["device_commands.device_id", "device_commands.status", "device_commands.output", "device_commands.requested_by", "device_commands.created_at", "device_commands.finished_at", "users.email"])
              .where("device_commands.action", "=", "updates")
              .orderBy("device_commands.device_id")
              .orderBy("device_commands.created_at", "desc")
              .execute()
          : [];
        const lastBy = new Map(last.map((r) => [r.device_id, r]));
        const cutoff = Date.now() - policy.deadline_days * 86_400_000;
        const data = devices.map((d) => {
          const since = policy.scope === "security" ? d.security_updates_since : d.updates_pending_since;
          const appsLate = policy.third_party && !!d.third_party_since && d.third_party_since.getTime() <= cutoff;
          const l = lastBy.get(d.id);
          return {
            device_id: d.id,
            hostname: d.hostname,
            platform: d.platform,
            os_version: d.os_version,
            last_seen_at: isoOrNull(d.last_seen_at),
            checked_at: isoOrNull(d.updates_checked_at),
            error: d.updates_error,
            pending: d.updates_pending,
            security_pending: d.security_updates_pending,
            pending_since: isoOrNull(d.updates_pending_since),
            security_since: isoOrNull(d.security_updates_since),
            apps_pending: d.third_party_pending,
            apps_since: isoOrNull(d.third_party_since),
            overdue: policy.enabled && ((!!since && since.getTime() <= cutoff) || appsLate),
            last_install: l ? installOf(l) : null,
          };
        });
        const reporting = data.filter((d) => d.checked_at);
        const summary = {
          devices: data.length,
          reporting: reporting.length,
          up_to_date: reporting.filter((d) => !d.error && d.pending === 0).length,
          with_security: data.filter((d) => d.security_pending > 0).length,
          apps_outdated: data.filter((d) => d.apps_pending > 0).length,
          overdue: data.filter((d) => d.overdue).length,
          failing_checks: data.filter((d) => d.error).length,
        };
        const { updated_at: _, ...pol } = policy;
        return { summary, policy: pol, data };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/devices/{id}/updates",
      tags: ["Devices"],
      summary: "A device's pending OS updates and recent installs",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: {
        200: json(z.object({ checked_at: z.string().nullable(), error: z.string().nullable(), available: UpdatesReport.shape.available, installs: z.array(Install) })),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const d = await tx.selectFrom("devices").select(["inventory", "updates_checked_at", "updates_error"]).where("id", "=", id).executeTakeFirst();
        if (!d) throw notFound("Device");
        const rep = UpdatesReport.safeParse((d.inventory as { updates?: unknown } | null)?.updates);
        const installs = await tx
          .selectFrom("device_commands")
          .leftJoin("users", "users.id", "device_commands.requested_by")
          .select(["device_commands.status", "device_commands.output", "device_commands.requested_by", "device_commands.created_at", "device_commands.finished_at", "users.email"])
          .where("device_commands.device_id", "=", id)
          .where("device_commands.action", "=", "updates")
          .orderBy("device_commands.created_at", "desc")
          .limit(20)
          .execute();
        return { checked_at: isoOrNull(d.updates_checked_at), error: d.updates_error, available: rep.success && !rep.data.error ? rep.data.available : [], installs: installs.map(installOf) };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/device-updates/install",
      tags: ["Devices"],
      summary: "Install pending OS updates (and optionally app updates) now",
      description:
        "Queues a signed install on the chosen devices that have updates pending (security only, or all). Each runs it on its next check-in (offline devices within a day) and restarts afterwards only if `restart` is `if_needed` and the OS asks for it. Needs `devices:updates` and a recent MFA.",
      security: bearer,
      request: body(
        z.object({
          target: Target,
          scope: Scope.default("security"),
          restart: Restart.default("never"),
          apps: z.boolean().default(false).openapi({ description: "Also update third-party apps (Chrome, Zoom…)" }),
          reason: z.string().trim().min(3).max(500),
        }),
      ),
      responses: { 201: json(z.object({ queued: z.number().int(), skipped_up_to_date: z.number().int(), skipped_not_reporting: z.number().int(), skipped_in_progress: z.number().int() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:updates");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        let q = tx.selectFrom("devices").select(["id", "updates_checked_at", "updates_pending", "security_updates_pending", "third_party_pending"]).where("status", "=", "active");
        if (input.target.device_ids?.length) q = q.where("id", "in", input.target.device_ids);
        if (input.target.group_id) q = q.where((eb) => eb.exists(eb.selectFrom("group_members").whereRef("group_members.user_id", "=", "devices.primary_user_id").where("group_members.group_id", "=", input.target.group_id!)));
        const found = await q.limit(MAX_TARGETS + 1).execute();
        if (found.length > MAX_TARGETS) throw badRequest("too_many_devices", `An install goes to at most ${MAX_TARGETS} devices; narrow the target`);
        if (!found.length) throw badRequest("no_devices", "No devices match");
        const reporting = found.filter((d) => d.updates_checked_at);
        const osPending = (d: (typeof found)[number]) => (input.scope === "security" ? d.security_updates_pending : d.updates_pending) > 0;
        const appsPending = (d: (typeof found)[number]) => input.apps && d.third_party_pending > 0;
        const pending = reporting.filter((d) => osPending(d) || appsPending(d));
        const who = { restart: input.restart, apps: input.apps, reason: input.reason, requestedBy: p.userId, ttlMs: MANUAL_TTL_MS };
        const ids = [
          ...(await queueInstalls(tx, p.orgId, pending.filter(osPending).map((d) => d.id), { ...who, scope: input.scope })),
          ...(await queueInstalls(tx, p.orgId, pending.filter((d) => !osPending(d)).map((d) => d.id), { ...who, scope: "none" })),
        ];
        const result = { queued: ids.length, skipped_up_to_date: reporting.length - pending.length, skipped_not_reporting: found.length - reporting.length, skipped_in_progress: pending.length - ids.length };
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.updates_install", target: { type: "organization", id: p.orgId }, details: { automatic: false, scope: input.scope, apps: input.apps, restart: input.restart, reason: input.reason, target: input.target, ...result, device_ids: ids.slice(0, 50) } });
        return result;
      });
      return c.json(out, 201);
    },
  );
}

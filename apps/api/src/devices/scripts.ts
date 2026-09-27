import { createHash } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { badRequest, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";

/**
 * Scripts on devices (like JumpCloud Commands): a library, and runs that send a script to chosen
 * devices as commands signed with the organization's key (the agent refuses anything else). It
 * runs as root or SYSTEM, so it's owner/admin only (devices:scripts), never an API key, and
 * needs a recent MFA; every run is audited with the script's hash.
 */

const Shell = z.enum(["sh", "bash", "zsh", "powershell"]);
const PLATFORMS: Record<z.infer<typeof Shell>, string[]> = { sh: ["macos", "linux"], bash: ["macos", "linux"], zsh: ["macos", "linux"], powershell: ["windows"] };
const MAX_TARGETS = 1000;
const RUN_TTL_MS = 24 * 3600_000; // offline devices pick it up within a day
const Target = z
  .object({ device_ids: z.array(Id).max(MAX_TARGETS).optional(), group_id: Id.optional(), all: z.literal(true).optional() })
  .refine((t) => [t.device_ids?.length ? 1 : 0, t.group_id ? 1 : 0, t.all ? 1 : 0].reduce((a, b) => a + b, 0) === 1, "Choose devices, a group, or all devices");

const ScriptIn = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().trim().max(500).default(""),
  shell: Shell,
  body: z.string().min(1).max(256 * 1024),
});
const ScriptOut = ScriptIn.extend({ id: Id, created_at: z.string(), updated_at: z.string() }).openapi("DeviceScript");
const toScript = (s: { id: string; name: string; description: string; shell: z.infer<typeof Shell>; body: string; created_at: Date; updated_at: Date }) => ({ ...s, created_at: iso(s.created_at), updated_at: iso(s.updated_at) });

const RunDevice = z.object({ device_id: Id, hostname: z.string(), status: z.string(), exit_code: z.number().int().nullable(), output: z.string(), truncated: z.boolean(), duration_ms: z.number().int().nullable(), finished_at: z.string().nullable() });
const RunSummary = z
  .object({ id: Id, name: z.string(), shell: z.string(), reason: z.string(), requested_by: z.string().nullable(), created_at: z.string(), expires_at: z.string(), devices: z.number().int(), succeeded: z.number().int(), failed: z.number().int(), pending: z.number().int() })
  .openapi("ScriptRun");

async function summaries(tx: Tx, ids?: string[]) {
  let q = tx
    .selectFrom("script_runs")
    .leftJoin("users", "users.id", "script_runs.requested_by")
    .select(["script_runs.id", "script_runs.name", "script_runs.shell", "script_runs.reason", "script_runs.created_at", "script_runs.expires_at", "script_runs.device_count", "users.email"])
    .select((eb) => [
      eb.selectFrom("device_commands").whereRef("device_commands.script_run_id", "=", "script_runs.id").where("status", "=", "done").select((x) => x.fn.countAll<number>().as("n")).as("ok"),
      eb.selectFrom("device_commands").whereRef("device_commands.script_run_id", "=", "script_runs.id").where("status", "in", ["failed", "expired", "canceled"]).select((x) => x.fn.countAll<number>().as("n")).as("bad"),
    ])
    .orderBy("script_runs.created_at", "desc")
    .limit(100);
  if (ids) q = q.where("script_runs.id", "in", ids);
  return (await q.execute()).map((r) => ({
    id: r.id,
    name: r.name,
    shell: r.shell,
    reason: r.reason,
    requested_by: r.email,
    created_at: iso(r.created_at),
    expires_at: iso(r.expires_at),
    devices: r.device_count,
    succeeded: Number(r.ok ?? 0),
    failed: Number(r.bad ?? 0),
    pending: r.device_count - Number(r.ok ?? 0) - Number(r.bad ?? 0),
  }));
}

export function registerScriptRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/device-scripts", tags: ["Devices"], summary: "The script library", security: bearer, responses: { 200: json(z.object({ data: z.array(ScriptOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:scripts");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) => tx.selectFrom("device_scripts").selectAll().orderBy("name").execute());
      return c.json({ data: rows.map(toScript) }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/device-scripts", tags: ["Devices"], summary: "Add a script to the library", security: bearer, request: body(ScriptIn), responses: { 201: json(ScriptOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:scripts");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const row = await tx.insertInto("device_scripts").values({ id: newId(), org_id: p.orgId, ...input, created_by: p.userId }).returningAll().executeTakeFirstOrThrow();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.script_saved", target: { type: "device_script", id: row.id, display: row.name }, details: { shell: row.shell, sha256: createHash("sha256").update(row.body).digest("hex") } });
        return toScript(row);
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "put", path: "/v1/device-scripts/{id}", tags: ["Devices"], summary: "Change a library script", security: bearer, request: { params: z.object({ id: Id }), ...body(ScriptIn) }, responses: { 200: json(ScriptOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:scripts");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const row = await tx.updateTable("device_scripts").set({ ...input, updated_at: new Date() }).where("id", "=", id).returningAll().executeTakeFirst();
        if (!row) throw notFound("Script");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.script_saved", target: { type: "device_script", id, display: row.name }, details: { shell: row.shell, sha256: createHash("sha256").update(row.body).digest("hex") } });
        return toScript(row);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/device-scripts/{id}", tags: ["Devices"], summary: "Remove a library script (past runs keep their copy)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:scripts");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.deleteFrom("device_scripts").where("id", "=", id).returning("name").executeTakeFirst();
        if (!r) throw notFound("Script");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.script_deleted", target: { type: "device_script", id, display: r.name } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/script-runs",
      tags: ["Devices"],
      summary: "Run a script on devices",
      description:
        "Sends the script to the chosen devices whose OS can run it (sh/bash/zsh: macOS and Linux; PowerShell: Windows) as signed commands. Each runs it as root/SYSTEM on its next check-in (offline devices within a day) and returns its exit code and output (up to 64 KB). Needs `devices:scripts` and a recent MFA.",
      security: bearer,
      request: body(
        z.object({
          script_id: Id.optional(),
          script: ScriptIn.pick({ name: true, shell: true, body: true }).optional().openapi({ description: "A one-off script, instead of one from the library" }),
          reason: z.string().trim().min(3).max(500),
          target: Target,
          timeout_seconds: z.number().int().min(5).max(1800).default(300),
        }),
      ),
      responses: { 201: json(RunSummary.extend({ skipped_incompatible: z.number().int() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:scripts");
      const input = c.req.valid("json");
      if (!!input.script_id === !!input.script) throw badRequest("invalid_request", "Give script_id or script, not both");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const s = input.script_id ? await tx.selectFrom("device_scripts").selectAll().where("id", "=", input.script_id).executeTakeFirst() : { id: null, ...input.script! };
        if (!s) throw notFound("Script");
        let q = tx.selectFrom("devices").select(["id", "platform"]).where("status", "=", "active");
        if (input.target.device_ids?.length) q = q.where("id", "in", input.target.device_ids);
        if (input.target.group_id) q = q.where((eb) => eb.exists(eb.selectFrom("group_members").whereRef("group_members.user_id", "=", "devices.primary_user_id").where("group_members.group_id", "=", input.target.group_id!)));
        const found = await q.limit(MAX_TARGETS + 1).execute();
        if (found.length > MAX_TARGETS) throw badRequest("too_many_devices", `A run goes to at most ${MAX_TARGETS} devices; narrow the target`);
        const targets = found.filter((d) => PLATFORMS[s.shell as z.infer<typeof Shell>].includes(d.platform));
        if (!targets.length) throw badRequest("no_devices", found.length ? `None of these devices can run ${s.shell} scripts` : "No devices match");
        const id = newId();
        const sha = createHash("sha256").update(s.body).digest("hex");
        const expires = new Date(Date.now() + RUN_TTL_MS);
        await tx.insertInto("script_runs").values({ id, org_id: p.orgId, script_id: s.id, name: s.name, shell: s.shell, body: s.body, body_sha256: sha, reason: input.reason, target: JSON.stringify(input.target), device_count: targets.length, requested_by: p.userId, expires_at: expires }).execute();
        await tx
          .insertInto("device_commands")
          .values(targets.map((d) => ({ id: newId(), org_id: p.orgId, device_id: d.id, action: "script" as const, channel: "agent" as const, reason: input.reason, requested_by: p.userId, expires_at: expires, args: JSON.stringify({ shell: s.shell, script: s.body, timeout_seconds: input.timeout_seconds }), query_id: null, script_run_id: id })))
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.script_run", target: { type: "script_run", id, display: s.name }, details: { shell: s.shell, sha256: sha, reason: input.reason, target: input.target, devices: targets.length, skipped: found.length - targets.length } });
        return { ...(await summaries(tx, [id]))[0]!, skipped_incompatible: found.length - targets.length };
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/script-runs", tags: ["Devices"], summary: "Recent script runs", security: bearer, responses: { 200: json(z.object({ data: z.array(RunSummary) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:scripts");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => summaries(tx)) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/script-runs/{id}",
      tags: ["Devices"],
      summary: "A script run: the script, and each device's exit code and output",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(RunSummary.extend({ body: z.string(), body_sha256: z.string(), results: z.array(RunDevice) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:scripts");
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const run = await tx.selectFrom("script_runs").select(["body", "body_sha256"]).where("id", "=", id).executeTakeFirst();
        if (!run) throw notFound("Script run");
        const rows = await tx
          .selectFrom("device_commands")
          .innerJoin("devices", "devices.id", "device_commands.device_id")
          .select(["device_commands.device_id", "devices.hostname", "device_commands.status", "device_commands.output", "device_commands.result", "device_commands.finished_at"])
          .where("device_commands.script_run_id", "=", id)
          .orderBy("devices.hostname")
          .execute();
        const results = rows.map((r) => {
          const res = (r.result ?? {}) as { exit_code?: number; output?: string; truncated?: boolean; duration_ms?: number };
          return { device_id: r.device_id, hostname: r.hostname, status: r.status, exit_code: res.exit_code ?? null, output: res.output ?? r.output, truncated: !!res.truncated, duration_ms: res.duration_ms ?? null, finished_at: r.finished_at ? iso(r.finished_at) : null };
        });
        return { ...(await summaries(tx, [id]))[0]!, ...run, results };
      });
      return c.json(out, 200);
    },
  );
}

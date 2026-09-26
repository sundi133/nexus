import { createRoute, z } from "@hono/zod-openapi";
import type { Context } from "hono";
import type { App, Env, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import type { Tx } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { compareVersions, releaseStore, type AgentRelease } from "./releases.js";
import { advance, evaluateRollout, fleet, getSettings, inStage, ringOf, STAGES, startRollout, supports } from "./updates.js";

const Stage = z.enum(STAGES);
// Named schemas are used nullable below via their unnamed base: `.nullable()` on a
// named schema would make the shared component itself nullable for every client.
const ReleaseBase = z.object({ version: z.string(), published_at: z.string(), notes: z.string(), platforms: z.array(z.string()).openapi({ example: ["darwin/arm64"] }) });
const ReleaseOut = ReleaseBase.openapi("AgentRelease");
const RolloutBase = z
  .object({
    id: Id,
    version: z.string(),
    stage: Stage,
    status: z.enum(["active", "paused", "halted", "completed", "cancelled"]),
    halted_reason: z.string(),
    stage_started_at: z.string(),
    next_advance_at: z.string().nullable().openapi({ description: "When the current stage advances by itself, if at least one of its devices updated healthily" }),
    created_at: z.string(),
    started_by: z.string(),
    stages: z.array(z.object({ stage: Stage, devices: z.number().int(), updated: z.number().int(), failed: z.number().int() })),
    devices: z.array(
      z.object({
        id: Id,
        hostname: z.string(),
        ring: Stage,
        state: z.enum(["updated", "offered", "waiting", "failed", "rolled_back", "unsupported"]),
        agent_version: z.string(),
        error: z.string(),
      }),
    ),
  });
const RolloutOut = RolloutBase.openapi("AgentRollout");
const Status = z
  .object({
    release_keys_configured: z.boolean(),
    latest: ReleaseBase.nullable(),
    releases: z.array(ReleaseOut),
    settings: z.object({ auto_rollout: z.boolean(), advance_after_hours: z.number().int() }),
    rollout: RolloutBase.nullable(),
    fleet: z.array(z.object({ version: z.string(), devices: z.number().int() })),
  })
  .openapi("AgentUpdateStatus");

const releaseOut = (r: AgentRelease) => ({ version: r.version, published_at: r.published_at, notes: r.notes, platforms: r.artifacts.map((a) => `${a.os}/${a.arch}`) });

async function status(c: Context<Env>, tx: Tx, p: Principal): Promise<z.infer<typeof Status>> {
  const deps = c.get("deps");
  const store = releaseStore(deps.cfg);
  const releases = await store.list();
  const settings = await getSettings(tx);
  await evaluateRollout(tx, p.orgId, store, c.get("meta"));
  const r = await tx.selectFrom("agent_rollouts").selectAll().orderBy("created_at", "desc").executeTakeFirst();
  const devices = await fleet(tx);

  const byVersion = new Map<string, number>();
  for (const d of devices) byVersion.set(d.agent_version || "unknown", (byVersion.get(d.agent_version || "unknown") ?? 0) + 1);
  const fleetOut = [...byVersion].map(([version, n]) => ({ version, devices: n })).sort((a, b) => compareVersions(b.version, a.version));

  let rollout: z.infer<typeof RolloutBase> | null = null;
  if (r) {
    const rel = releases.find((x) => x.version === r.version);
    const results = new Map(
      (await tx.selectFrom("device_updates").select(["device_id", "state", "error"]).where("version", "=", r.version).execute()).map((u) => [u.device_id, u]),
    );
    const rows = devices.map((d) => {
      const u = results.get(d.id);
      const state =
        compareVersions(d.agent_version, r.version) >= 0
          ? ("updated" as const)
          : u?.state === "failed" || u?.state === "rolled_back"
            ? u.state
            : !rel || !supports(rel, d)
              ? ("unsupported" as const)
              : u?.state === "offered" && inStage(r, d.id)
                ? ("offered" as const)
                : ("waiting" as const);
      return { id: d.id, hostname: d.hostname, ring: ringOf(r, d.id), state, agent_version: d.agent_version, error: u?.error ?? "" };
    });
    const creator = r.created_by ? await tx.selectFrom("users").select("email").where("id", "=", r.created_by).executeTakeFirst() : null;
    const ringIdx = (s: (typeof STAGES)[number]) => STAGES.indexOf(s);
    rollout = {
      id: r.id,
      version: r.version,
      stage: r.stage,
      status: r.status,
      halted_reason: r.halted_reason,
      stage_started_at: iso(r.stage_started_at),
      next_advance_at:
        r.status === "active" && r.stage !== "all" && settings.advance_after_hours > 0 ? new Date(r.stage_started_at.getTime() + settings.advance_after_hours * 3600_000).toISOString() : null,
      created_at: iso(r.created_at),
      started_by: creator?.email ?? "Nexus (automatic)",
      // Cumulative: "early" includes the canaries, "all" is the whole fleet.
      stages: STAGES.map((s) => {
        const inIt = rows.filter((x) => ringIdx(x.ring) <= ringIdx(s));
        return { stage: s, devices: inIt.length, updated: inIt.filter((x) => x.state === "updated").length, failed: inIt.filter((x) => x.state === "failed" || x.state === "rolled_back").length };
      }),
      devices: rows.sort((a, b) => ringIdx(a.ring) - ringIdx(b.ring) || a.hostname.localeCompare(b.hostname)).slice(0, 500),
    };
  }
  return {
    release_keys_configured: deps.cfg.agentReleaseKeys.trim() !== "",
    latest: releases[0] ? releaseOut(releases[0]) : null,
    releases: releases.slice(0, 10).map(releaseOut),
    settings,
    rollout,
    fleet: fleetOut,
  };
}

async function stepUp(c: Context<Env>, tx: Tx, p: Principal) {
  requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
}

export function registerAgentUpdateRoutes(app: App) {
  const ok = { 200: json(Status), ...problemResponses };

  app.openapi(
    createRoute({ method: "get", path: "/v1/agent-updates", tags: ["Devices"], summary: "Agent releases, rollout progress and fleet versions", security: bearer, responses: ok }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      return c.json(await c.get("deps").db.tenant(p.orgId, (tx) => status(c, tx, p)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/agent-updates/settings",
      tags: ["Devices"],
      summary: "Agent update settings (requires recent MFA)",
      security: bearer,
      request: body(z.object({ auto_rollout: z.boolean(), advance_after_hours: z.number().int().min(0).max(720) })),
      responses: ok,
    }),
    async (c) => {
      const p = requirePermission(c, "devices:updates");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        const before = await getSettings(tx);
        await tx
          .insertInto("agent_update_settings")
          .values({ org_id: p.orgId, ...input, updated_at: new Date() })
          .onConflict((oc) => oc.column("org_id").doUpdateSet({ ...input, updated_at: new Date() }))
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "agent.update_settings_changed", target: { type: "organization", id: p.orgId }, details: { from: before, to: input } });
        return status(c, tx, p);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/agent-updates/rollouts",
      tags: ["Devices"],
      summary: "Start rolling out a release (requires recent MFA)",
      description: "Replaces any unfinished rollout. Canaries default to ~1% of the fleet (at least one device), preferring devices seen in the last hour.",
      security: bearer,
      request: body(z.object({ version: z.string().max(40), canary_device_ids: z.array(Id).max(50).optional() })),
      responses: { 201: json(Status, "Started"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:updates");
      const input = c.req.valid("json");
      const rel = await releaseStore(c.get("deps").cfg).get(input.version);
      if (!rel) throw notFound("Release");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await stepUp(c, tx, p);
        try {
          await startRollout(tx, p.orgId, rel, { principal: p, meta: c.get("meta") }, input.canary_device_ids);
        } catch (err) {
          if (err instanceof Error && err.message.startsWith("Not an active device")) throw badRequest("invalid_canaries", err.message);
          throw err;
        }
        return status(c, tx, p);
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/agent-updates/rollouts/{id}/actions",
      tags: ["Devices"],
      summary: "Pause, resume, advance or cancel a rollout",
      description: "Pausing and cancelling only stop the spread, so they don't need recent MFA; resuming and advancing do.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ action: z.enum(["pause", "resume", "advance", "cancel"]) })) },
      responses: ok,
    }),
    async (c) => {
      const p = requirePermission(c, "devices:updates");
      const { id } = c.req.valid("param");
      const { action } = c.req.valid("json");
      const meta = c.get("meta");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.selectFrom("agent_rollouts").selectAll().where("id", "=", id).executeTakeFirst();
        if (!r) throw notFound("Rollout");
        const now = new Date();
        const allowed: Record<typeof action, string[]> = { pause: ["active"], resume: ["paused", "halted"], advance: ["active", "paused"], cancel: ["active", "paused", "halted"] };
        if (!allowed[action].includes(r.status)) throw conflict("invalid_state", `Can't ${action} a rollout that is ${r.status}`);
        if (action === "resume" || action === "advance") await stepUp(c, tx, p);
        const who = { principal: p, meta };
        const target = { type: "agent_rollout", id: r.id, display: r.version };
        if (action === "advance") {
          if (r.stage === "all") throw conflict("invalid_state", "This rollout already covers every device");
          await advance(tx, p.orgId, r, who, now);
        } else {
          const next = action === "pause" ? "paused" : action === "cancel" ? "cancelled" : "active";
          // Resuming forgives the failures that halted it; failed devices still aren't re-offered this version.
          await tx
            .updateTable("agent_rollouts")
            .set({ status: next, updated_at: now, ...(action === "resume" ? { failures_since: now, halted_reason: "" } : {}) })
            .where("id", "=", r.id)
            .execute();
          await audit(tx, p.orgId, who, { type: `agent.rollout_${action === "pause" ? "paused" : action === "cancel" ? "cancelled" : "resumed"}`, target });
        }
        return status(c, tx, p);
      });
      return c.json(out, 200);
    },
  );
}

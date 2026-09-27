import { createHash, randomBytes } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { assertDeviceInScope, requirePermission, requireRecentMfa } from "../auth/guard.js";
import { consumeProof, deviceFromProof } from "../devices/agent-api.js";
import { ONLINE_WINDOW_MS } from "../devices/service.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, conflict, forbidden, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, json, problemResponses } from "../schemas.js";

/**
 * Remote Assist (see docs/REMOTE-ASSIST.md). An admin asks to see a Mac's screen with a reason;
 * the agent asks the person at the Mac; if they allow it, the agent turns on macOS Screen Sharing
 * and tunnels it to the relay here, and the requester's browser views it. Nothing is viewable
 * without that approval, only the requester can view, and every step is audited.
 */

/** How long the person at the Mac has to answer (the command may wait up to a check-in to arrive). */
export const ASK_MS = 3 * 60_000;
const TICKET_MS = 60_000;

const Status = z.enum(["asking", "active", "declined", "ended", "expired", "failed"]);
const SessionOut = z
  .object({
    id: Id,
    device_id: Id,
    hostname: z.string(),
    status: Status,
    detail: z.string(),
    reason: z.string(),
    requested_by: z.string().nullable().openapi({ description: "The requester's email" }),
    mine: z.boolean().openapi({ description: "You asked for it, so you're the one who can view it" }),
    created_at: z.string(),
    accepted_at: z.string().nullable(),
    ended_at: z.string().nullable(),
    expires_at: z.string().openapi({ description: "While asking: the approval deadline. While active: when it ends on its own" }),
  })
  .openapi("RemoteAssistSession");

export const hashTicket = (t: string) => createHash("sha256").update(t).digest("hex");

/** Sessions past their deadline are closed when anything looks at them (no background job needed). */
export async function settleExpired(tx: Tx, where: { deviceId?: string; id?: string }) {
  for (const [from, to, detail] of [
    ["asking", "expired", "Nobody answered in time"],
    ["active", "ended", "Reached its time limit"],
  ] as const) {
    let q = tx.updateTable("remote_assist_sessions").set({ status: to, detail, ended_at: new Date(), ticket_hash: null }).where("status", "=", from).where("expires_at", "<", new Date());
    if (where.deviceId) q = q.where("device_id", "=", where.deviceId);
    if (where.id) q = q.where("id", "=", where.id);
    await q.execute();
  }
}

async function load(tx: Tx, id: string, userId: string) {
  await settleExpired(tx, { id });
  const r = await tx
    .selectFrom("remote_assist_sessions as s")
    .innerJoin("devices", "devices.id", "s.device_id")
    .leftJoin("users", "users.id", "s.requested_by")
    .select(["s.id", "s.device_id", "devices.hostname", "s.status", "s.detail", "s.reason", "users.email", "s.requested_by", "s.created_at", "s.accepted_at", "s.ended_at", "s.expires_at"])
    .where("s.id", "=", id)
    .executeTakeFirst();
  if (!r) throw notFound("Session");
  return {
    out: {
      id: r.id,
      device_id: r.device_id,
      hostname: r.hostname,
      status: r.status,
      detail: r.detail,
      reason: r.reason,
      requested_by: r.email,
      mine: r.requested_by === userId,
      created_at: r.created_at.toISOString(),
      accepted_at: r.accepted_at?.toISOString() ?? null,
      ended_at: r.ended_at?.toISOString() ?? null,
      expires_at: r.expires_at.toISOString(),
    },
    requestedBy: r.requested_by,
  };
}

/** Closes the relay's connections for a session (set by the relay once it's attached to the server). */
export const relayHooks: { end: (sessionId: string) => void } = { end: () => {} };

export function registerRemoteAssistRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/devices/{id}/remote-assist",
      tags: ["Devices"],
      summary: "Ask to see a Mac's screen (the person at the Mac must allow it)",
      description:
        "Needs `devices:actions` and a recent MFA. The agent asks the signed-in person; if they allow it, the session becomes `active` and you (only you) can view it until it ends, at most `minutes` later.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ reason: z.string().trim().min(3).max(300), minutes: z.number().int().min(5).max(120).default(60) })) },
      responses: { 201: json(SessionOut, "Asked"), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:actions", { scoped: true });
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertDeviceInScope(tx, p, "devices:actions", id);
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const d = await tx.selectFrom("devices").select(["hostname", "platform", "last_seen_at"]).where("id", "=", id).where("status", "=", "active").executeTakeFirst();
        if (!d) throw notFound("Device");
        if (d.platform !== "macos") throw conflict("unsupported_platform", "Remote Assist works on Macs for now");
        if (!d.last_seen_at || Date.now() - d.last_seen_at.getTime() > ONLINE_WINDOW_MS) throw conflict("device_offline", `${d.hostname} isn't online, so nobody can allow the request`);
        await settleExpired(tx, { deviceId: id });
        const open = await tx.selectFrom("remote_assist_sessions").select("id").where("device_id", "=", id).where("status", "in", ["asking", "active"]).executeTakeFirst();
        if (open) throw new ApiError(409, "session_open", "There's already a Remote Assist session on this Mac: end it first", { session_id: open.id });

        const sid = newId();
        const cid = newId();
        const expires = new Date(Date.now() + ASK_MS);
        await tx
          .insertInto("device_commands")
          .values({
            id: cid,
            org_id: p.orgId,
            device_id: id,
            action: "remote_assist",
            channel: "agent",
            reason: input.reason,
            requested_by: p.userId,
            expires_at: new Date(Date.now() + ASK_MS - 60_000), // leaves the person a minute to answer
            args: JSON.stringify({ session_id: sid, requester: p.email, reason: input.reason, minutes: input.minutes }),
          })
          .execute();
        await tx.insertInto("remote_assist_sessions").values({ id: sid, org_id: p.orgId, device_id: id, requested_by: p.userId, reason: input.reason, command_id: cid, expires_at: expires }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "remote_assist.requested", target: { type: "device", id, display: d.hostname }, details: { session_id: sid, reason: input.reason, minutes: input.minutes } });
        return (await load(tx, sid, p.userId)).out;
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/devices/{id}/remote-assist", tags: ["Devices"], summary: "Recent Remote Assist sessions on a device", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(z.object({ data: z.array(SessionOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:actions", { scoped: true });
      const { id } = c.req.valid("param");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertDeviceInScope(tx, p, "devices:actions", id);
        await settleExpired(tx, { deviceId: id });
        const ids = await tx.selectFrom("remote_assist_sessions").select("id").where("device_id", "=", id).orderBy("created_at", "desc").limit(20).execute();
        return Promise.all(ids.map(async (r) => (await load(tx, r.id, p.userId)).out));
      });
      return c.json({ data }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/remote-assist/sessions/{id}", tags: ["Devices"], summary: "A Remote Assist session", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(SessionOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:actions", { scoped: true });
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await load(tx, id, p.userId);
        await assertDeviceInScope(tx, p, "devices:actions", s.out.device_id);
        return s.out;
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/remote-assist/sessions/{id}/ticket",
      tags: ["Devices"],
      summary: "A one-time ticket to open the session's viewer (the requester only)",
      description: "Open a websocket to `ws_url` within a minute, offering the subprotocols `binary` and `nexus-ticket.<ticket>`. The stream is the Mac's Screen Sharing (RFB/VNC).",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ ticket: z.string(), ws_url: z.string(), expires_at: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:actions", { scoped: true });
      const { id } = c.req.valid("param");
      const deps = c.get("deps");
      const ticket = randomBytes(24).toString("base64url");
      const expires = new Date(Date.now() + TICKET_MS);
      await deps.db.tenant(p.orgId, async (tx) => {
        const s = await load(tx, id, p.userId);
        if (!s.out.mine) throw forbidden("Only the person who asked can view: the person at the Mac allowed them, not everyone");
        if (s.out.status !== "active") throw conflict("not_active", s.out.status === "asking" ? "The person at the Mac hasn't allowed it yet" : "This session is over");
        await tx.updateTable("remote_assist_sessions").set({ ticket_hash: hashTicket(ticket), ticket_expires_at: expires }).where("id", "=", id).execute();
      });
      const base = new URL(deps.cfg.apiPublicUrl);
      base.protocol = base.protocol === "https:" ? "wss:" : "ws:";
      return c.json({ ticket, ws_url: new URL(`/v1/remote-assist/sessions/${id}/view`, base).toString(), expires_at: expires.toISOString() }, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/remote-assist/sessions/{id}/end", tags: ["Devices"], summary: "End a Remote Assist session (or withdraw the request)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(SessionOut), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:actions", { scoped: true });
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await load(tx, id, p.userId);
        await assertDeviceInScope(tx, p, "devices:actions", s.out.device_id);
        if (s.out.status === "asking" || s.out.status === "active") {
          await tx.updateTable("remote_assist_sessions").set({ status: "ended", detail: `Ended by ${p.email}`, ended_at: new Date(), ticket_hash: null }).where("id", "=", id).execute();
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "remote_assist.ended", target: { type: "device", id: s.out.device_id, display: s.out.hostname }, details: { session_id: id, by: "admin" } });
        }
        return (await load(tx, id, p.userId)).out;
      });
      relayHooks.end(id);
      return c.json(out, 200);
    },
  );

  // What the person at the Mac decided, and how it ended (called by the agent).
  const AgentState = z.object({ state: z.enum(["accepted", "declined", "ended", "failed"]), detail: z.string().max(300).default("") });
  app.openAPIRegistry.registerPath({
    method: "post",
    path: "/v1/agent/remote-assist/{id}/state",
    tags: ["Agent"],
    summary: "Report a Remote Assist decision or ending (called by the Nexus agent)",
    description: "Body `{state: accepted|declined|ended|failed, detail}`, signed with the device key.",
    responses: { 204: { description: "Recorded" } },
  });
  app.post("/v1/agent/remote-assist/:id/state", async (c) => {
    const deps = c.get("deps");
    const id = c.req.param("id");
    const raw = await c.req.text();
    const h = c.req.header("authorization") ?? "";
    if (!h.startsWith("NexusDevice ")) throw new ApiError(401, "device_auth_required", "Missing device signature");
    const { dev, kid, payload } = await deviceFromProof(deps, { method: c.req.method, path: c.req.path }, h.slice(12).trim(), raw);
    let input: z.infer<typeof AgentState>;
    try {
      input = AgentState.parse(JSON.parse(raw));
    } catch {
      throw badRequest("invalid_request", "Expected {state, detail}");
    }
    await deps.db.tenant(dev.org_id, async (tx) => {
      await consumeProof(tx, dev.org_id, kid, payload);
      if (!/^[0-9a-f-]{36}$/.test(id)) throw notFound("Session");
      await settleExpired(tx, { id });
      const s = await tx
        .selectFrom("remote_assist_sessions")
        .innerJoin("devices", "devices.id", "remote_assist_sessions.device_id")
        .select(["remote_assist_sessions.status", "remote_assist_sessions.reason", "devices.hostname"])
        .select((eb) => eb.ref("remote_assist_sessions.expires_at").as("expires_at"))
        .where("remote_assist_sessions.id", "=", id)
        .where("remote_assist_sessions.device_id", "=", kid)
        .executeTakeFirst();
      if (!s) throw notFound("Session");
      const allowed: Record<string, string[]> = { accepted: ["asking"], declined: ["asking"], failed: ["asking", "active"], ended: ["active"] };
      if (!allowed[input.state]!.includes(s.status)) throw conflict("session_closed", "This session is already over");
      const detail = input.detail.replace(/[\r\n]+/g, " ").trim();
      if (input.state === "accepted") {
        const cmd = await tx.selectFrom("device_commands").select("args").innerJoin("remote_assist_sessions", "remote_assist_sessions.command_id", "device_commands.id").where("remote_assist_sessions.id", "=", id).executeTakeFirst();
        const minutes = Number((cmd?.args as { minutes?: number } | null)?.minutes ?? 60);
        await tx.updateTable("remote_assist_sessions").set({ status: "active", detail, accepted_at: new Date(), expires_at: new Date(Date.now() + minutes * 60_000) }).where("id", "=", id).execute();
      } else {
        await tx.updateTable("remote_assist_sessions").set({ status: input.state, detail, ended_at: new Date(), ticket_hash: null }).where("id", "=", id).execute();
      }
      await audit(tx, dev.org_id, { meta: c.get("meta") }, {
        type: `remote_assist.${input.state}`,
        outcome: input.state === "failed" ? "failure" : "success",
        actor: { type: "system", id: null, display: s.hostname },
        target: { type: "device", id: kid, display: s.hostname },
        details: { session_id: id, ...(detail ? { detail } : {}) },
      });
    });
    if (input.state !== "accepted") relayHooks.end(id);
    return c.body(null, 204);
  });
}

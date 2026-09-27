import type { IncomingMessage, Server } from "node:http";
import type { Duplex } from "node:stream";
import { sql } from "kysely";
import { WebSocket, WebSocketServer } from "ws";
import type { Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { consumeProof, deviceFromProof } from "../devices/agent-api.js";
import { ApiError } from "../platform/errors.js";
import { hashTicket, relayHooks, settleExpired } from "./routes.js";

/**
 * The Remote Assist relay: websockets on the API's own port.
 *
 * - The agent keeps one idle tunnel open per session (`/v1/agent/remote-assist/{id}/tunnel`,
 *   signed with the device key). When a viewer arrives, the relay sends the tunnel the text frame
 *   "open"; the agent connects it to the Mac's Screen Sharing and the two are piped together
 *   (binary frames both ways). When either side closes, so does the other, and the agent opens a
 *   new idle tunnel.
 * - The requester's browser connects to `/v1/remote-assist/sessions/{id}/view` with a one-time
 *   ticket in its subprotocols (browsers can't set headers on websockets).
 *
 * Both ends must reach the same API instance: with several, route /v1/agent/remote-assist/ and
 * /v1/remote-assist/ to one (see docs/REMOTE-ASSIST.md).
 */

const AGENT_PATH = /^\/v1\/agent\/remote-assist\/([0-9a-f-]{36})\/tunnel$/;
const VIEW_PATH = /^\/v1\/remote-assist\/sessions\/([0-9a-f-]{36})\/view$/;
const WAIT_FOR_AGENT_MS = 15_000;
const CHECK_EVERY_MS = 10_000;
const MAX_IDLE_TUNNELS = 2;

type Session = { orgId: string; idle: WebSocket[]; waiting: ((a: WebSocket) => void)[]; live: Set<WebSocket> };

export type Relay = { end: (id: string) => void; close: () => void };

const STATUS_TEXT: Record<number, string> = { 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 409: "Conflict", 410: "Gone", 500: "Internal Server Error" };

function refuse(socket: Duplex, status: number, code: string, message: string) {
  const body = JSON.stringify({ status, code, title: message });
  socket.write(`HTTP/1.1 ${status} ${STATUS_TEXT[status] ?? "Error"}\r\ncontent-type: application/problem+json\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`);
  socket.destroy();
}

export function attachRemoteAssistRelay(server: Server, deps: Deps): Relay {
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: 8 * 1024 * 1024,
    // A viewer offers ["binary", "nexus-ticket.<ticket>"]: answer with "binary", never echo the ticket.
    handleProtocols: (protocols) => (protocols.has("binary") ? "binary" : false),
  });
  const sessions = new Map<string, Session>();
  const session = (id: string, orgId: string) => {
    let s = sessions.get(id);
    if (!s) sessions.set(id, (s = { orgId, idle: [], waiting: [], live: new Set() }));
    return s;
  };
  const closeAll = (id: string, reason: string) => {
    const s = sessions.get(id);
    if (!s) return;
    sessions.delete(id);
    for (const ws of [...s.idle, ...s.live]) ws.close(4000, reason);
  };
  const forget = (id: string) => {
    const s = sessions.get(id);
    if (s && !s.idle.length && !s.live.size && !s.waiting.length) sessions.delete(id);
  };

  // Sessions end elsewhere too (time limit, another instance): check the ones with connections.
  const timer = setInterval(async () => {
    for (const [id, s] of sessions) {
      const status = await deps.db
        .tenant(s.orgId, async (tx) => {
          await settleExpired(tx, { id });
          return (await tx.selectFrom("remote_assist_sessions").select("status").where("id", "=", id).executeTakeFirst())?.status;
        })
        .catch(() => "active"); // a database blip isn't a reason to cut someone off
      if (status !== "active") closeAll(id, "Session ended");
    }
  }, CHECK_EVERY_MS);
  timer.unref();
  relayHooks.end = (id) => closeAll(id, "Session ended");

  function pair(agent: WebSocket, viewer: WebSocket, s: Session) {
    s.live.add(agent);
    s.live.add(viewer);
    agent.send("open");
    agent.on("message", (data, binary) => {
      if (binary && viewer.readyState === WebSocket.OPEN) viewer.send(data, { binary: true });
    });
    viewer.on("message", (data, binary) => {
      if (binary && agent.readyState === WebSocket.OPEN) agent.send(data, { binary: true });
    });
    const done = () => {
      s.live.delete(agent);
      s.live.delete(viewer);
      if (agent.readyState === WebSocket.OPEN) agent.close(1000, "Viewer left");
      if (viewer.readyState === WebSocket.OPEN) viewer.close(1000, "The Mac's side closed");
    };
    agent.on("close", done);
    viewer.on("close", done);
  }

  async function agentUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, id: string, path: string) {
    const auth = req.headers.authorization ?? "";
    if (!auth.startsWith("NexusDevice ")) return refuse(socket, 401, "device_auth_required", "Missing device signature");
    const { dev, kid, payload } = await deviceFromProof(deps, { method: "GET", path }, auth.slice(12).trim(), "");
    const ok = await deps.db.tenant(dev.org_id, async (tx) => {
      await consumeProof(tx, dev.org_id, kid, payload);
      await settleExpired(tx, { id });
      return !!(await tx.selectFrom("remote_assist_sessions").select("id").where("id", "=", id).where("device_id", "=", kid).where("status", "=", "active").executeTakeFirst());
    });
    // 410 tells the agent to stop and turn Screen Sharing back off.
    if (!ok) return refuse(socket, 410, "session_over", "This Remote Assist session isn't active");
    wss.handleUpgrade(req, socket, head, (ws) => {
      const s = session(id, dev.org_id);
      const waiter = s.waiting.shift();
      if (waiter) return waiter(ws);
      s.idle.push(ws);
      while (s.idle.length > MAX_IDLE_TUNNELS) s.idle.shift()!.close(1000, "Too many idle tunnels");
      ws.on("close", () => {
        s.idle = s.idle.filter((w) => w !== ws);
        forget(id);
      });
    });
  }

  async function viewerUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer, id: string) {
    // The ticket authenticates; the origin check keeps other sites from using one they got hold of.
    if (req.headers.origin !== new URL(deps.cfg.publicUrl).origin) return refuse(socket, 403, "bad_origin", "Open the viewer from the Nexus console");
    const offered = String(req.headers["sec-websocket-protocol"] ?? "").split(",").map((p) => p.trim());
    const ticket = offered.find((p) => p.startsWith("nexus-ticket."))?.slice("nexus-ticket.".length);
    if (!ticket || !offered.includes("binary")) return refuse(socket, 401, "ticket_required", "Missing viewer ticket");
    const hash = hashTicket(ticket);
    const found = await deps.db.unscoped(async (tx) => (await sql<{ session_id: string; org_id: string }>`SELECT * FROM nexus_remote_assist_ticket(${hash})`.execute(tx)).rows[0]);
    if (!found || found.session_id !== id) return refuse(socket, 401, "bad_ticket", "That viewer ticket is invalid or used");
    const claimed = await deps.db.tenant(found.org_id, async (tx) => {
      // One use: the ticket is cleared as it's spent.
      const s = await tx
        .updateTable("remote_assist_sessions")
        .set({ ticket_hash: null, ticket_expires_at: null })
        .where("id", "=", id)
        .where("ticket_hash", "=", hash)
        .where("status", "=", "active")
        .returning(["device_id", "requested_by"])
        .executeTakeFirst();
      if (!s) return false;
      const d = await tx.selectFrom("devices").select("hostname").where("id", "=", s.device_id).executeTakeFirst();
      const u = s.requested_by ? await tx.selectFrom("users").select("email").where("id", "=", s.requested_by).executeTakeFirst() : undefined;
      await audit(tx, found.org_id, { meta: { ip: req.socket.remoteAddress ?? "", userAgent: String(req.headers["user-agent"] ?? ""), requestId: "" } }, {
        type: "remote_assist.viewed",
        actor: { type: "user", id: s.requested_by, display: u?.email ?? "" },
        target: { type: "device", id: s.device_id, display: d?.hostname ?? "" },
        details: { session_id: id },
      });
      return true;
    });
    if (!claimed) return refuse(socket, 401, "bad_ticket", "That viewer ticket is invalid or used");
    wss.handleUpgrade(req, socket, head, (viewer) => {
      const s = session(id, found.org_id);
      const agent = s.idle.shift();
      if (agent) return pair(agent, viewer, s);
      // The agent opens a fresh tunnel after each viewer, so one is usually a moment away.
      const t = setTimeout(() => {
        s.waiting = s.waiting.filter((w) => w !== take);
        viewer.close(4004, "The Mac isn't connected to Nexus right now");
        forget(id);
      }, WAIT_FOR_AGENT_MS);
      const take = (a: WebSocket) => {
        clearTimeout(t);
        pair(a, viewer, s);
      };
      s.waiting.push(take);
      viewer.on("close", () => {
        clearTimeout(t);
        s.waiting = s.waiting.filter((w) => w !== take);
        forget(id);
      });
    });
  }

  const onUpgrade = (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const a = AGENT_PATH.exec(path);
    const v = VIEW_PATH.exec(path);
    if (!a && !v) return refuse(socket, 404, "not_found", "Not found");
    socket.on("error", () => socket.destroy());
    (a ? agentUpgrade(req, socket, head, a[1]!, path) : viewerUpgrade(req, socket, head, v![1]!)).catch((err: unknown) => {
      if (err instanceof ApiError) refuse(socket, err.status, err.code, err.message);
      else {
        console.error("remote assist upgrade failed", err);
        refuse(socket, 500, "internal", "Something went wrong");
      }
    });
  };
  server.on("upgrade", onUpgrade);

  return {
    end: (id) => closeAll(id, "Session ended"),
    close: () => {
      clearInterval(timer);
      server.off("upgrade", onUpgrade);
      for (const id of [...sessions.keys()]) closeAll(id, "Server stopping");
      wss.close();
    },
  };
}

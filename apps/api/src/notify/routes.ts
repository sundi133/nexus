import { createRoute, z } from "@hono/zod-openapi";
import { streamSSE } from "hono/streaming";
import type { App } from "../context.js";
import { requireSession } from "../auth/guard.js";
import { decodeCursor, pageOf } from "../platform/pagination.js";
import type { RealtimeEvent } from "../platform/realtime.js";
import type { Tx } from "../platform/db.js";
import { bearer, Cursor, Id, iso, json, Notification, problemResponses } from "../schemas.js";

const inbox = (tx: Tx, userId: string) =>
  tx.selectFrom("notifications").selectAll().where("recipient_user_id", "=", userId).where("archived_at", "is", null);

type Row = Awaited<ReturnType<ReturnType<typeof inbox>["executeTakeFirstOrThrow"]>>;

const toNotification = (n: Row) => ({
  id: n.id,
  category: n.category,
  severity: n.severity,
  title: n.title,
  body: n.body,
  entity: n.entity_type && n.entity_id ? { type: n.entity_type, id: n.entity_id } : null,
  link: n.link,
  actions: n.actions,
  read: n.read_at !== null,
  created_at: iso(n.created_at),
});

const InboxPage = z
  .object({ data: z.array(Notification), unread_count: z.number().int(), next_cursor: z.string().nullable() })
  .openapi("InboxPage");

export function registerNotificationRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/notifications",
      tags: ["Notifications"],
      summary: "My notification inbox (shared by web and mobile)",
      security: bearer,
      request: { query: Cursor.extend({ filter: z.enum(["all", "unread"]).default("all") }) },
      responses: { 200: json(InboxPage), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const q = c.req.valid("query");
      const after = decodeCursor(q.cursor);
      const { rows, unread } = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        let query = inbox(tx, p.userId).orderBy("id", "desc").limit(q.limit + 1);
        if (after) query = query.where("id", "<", after);
        if (q.filter === "unread") query = query.where("read_at", "is", null);
        const unread = await inbox(tx, p.userId)
          .where("read_at", "is", null)
          .clearSelect()
          .select((eb) => eb.fn.countAll<number>().as("n"))
          .executeTakeFirstOrThrow();
        return { rows: await query.execute(), unread: Number(unread.n) };
      });
      const pg = pageOf(rows, q.limit);
      return c.json({ data: pg.data.map(toNotification), unread_count: unread, next_cursor: pg.next_cursor }, 200);
    },
  );

  const mark = (path: string, summary: string, set: "read_at" | "archived_at", all = false) =>
    app.openapi(
      createRoute({
        method: "post",
        path,
        tags: ["Notifications"],
        summary,
        security: bearer,
        request: all ? {} : { params: z.object({ id: Id }) },
        responses: { 204: { description: "Done" }, ...problemResponses },
      }),
      async (c) => {
        const p = requireSession(c);
        const id = all ? null : (c.req.param("id") ?? null);
        await c.get("deps").db.tenant(p.orgId, (tx) => {
          let q = tx.updateTable("notifications").set({ [set]: new Date() }).where("recipient_user_id", "=", p.userId).where(set, "is", null);
          if (id) q = q.where("id", "=", id);
          return q.execute();
        });
        return c.body(null, 204);
      },
    );

  mark("/v1/me/notifications/{id}/read", "Mark a notification as read", "read_at");
  mark("/v1/me/notifications/{id}/archive", "Archive a notification", "archived_at");
  mark("/v1/me/notifications/read-all", "Mark all notifications as read", "read_at", true);

  // ---- Real-time stream ---------------------------------------------------------

  app.openAPIRegistry.registerPath({
    method: "get",
    path: "/v1/me/stream",
    tags: ["Notifications"],
    summary: "Server-Sent Events: real-time inbox and MFA challenge updates",
    description:
      "Events: `ready`, `notification` ({id, op}), `challenge` ({id, status}), `ping`. Payloads carry IDs only; fetch details from the REST API. Clients should reconnect with backoff.",
    security: bearer,
    responses: { 200: { description: "text/event-stream", content: { "text/event-stream": { schema: { type: "string" } } } } },
  });

  app.get("/v1/me/stream", (c) => {
    const p = requireSession(c, { allowPendingMfa: true });
    const { realtime } = c.get("deps");
    return streamSSE(c, async (stream) => {
      const queue: RealtimeEvent[] = [];
      let wake: (() => void) | null = null;
      const push = (e: RealtimeEvent) => {
        // Pending-MFA sessions may only observe their own sign-in challenge.
        if (p.sessionState === "pending_mfa" && !(e.kind === "challenge" && e.data.session_id === p.sessionId)) return;
        queue.push(e);
        wake?.();
      };
      const unsub =
        p.sessionState === "pending_mfa"
          ? realtime.subscribe(`session:${p.sessionId}`, push)
          : realtime.subscribe(`user:${p.userId}`, push);
      let open = true;
      stream.onAbort(() => {
        open = false;
        unsub();
        wake?.();
      });

      await stream.writeSSE({ event: "ready", data: JSON.stringify({ session_id: p.sessionId }) });
      while (open) {
        if (queue.length === 0) {
          await new Promise<void>((resolve) => {
            wake = resolve;
            setTimeout(resolve, 25_000); // keep proxies from closing idle connections
          });
          wake = null;
        }
        if (!open) break;
        if (queue.length === 0) {
          await stream.writeSSE({ event: "ping", data: "{}" });
          continue;
        }
        const e = queue.shift()!;
        if (e.kind === "inbox") {
          await stream.writeSSE({ event: "notification", id: e.data.id, data: JSON.stringify({ id: e.data.id, op: e.data.op }) });
        } else {
          await stream.writeSSE({ event: "challenge", data: JSON.stringify({ id: e.data.id, status: e.data.status }) });
        }
      }
    });
  });
}

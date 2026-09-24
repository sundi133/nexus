import { cookies } from "next/headers";
import { API_URL, csrfOk, forwardHeaders, problemResponse, SESSION_COOKIE } from "@/lib/session";

/**
 * Transparent proxy: /bff/v1/* → API /v1/*, attaching the session token from
 * the HttpOnly cookie. It adds no business logic; the browser never sees the
 * token. Responses (including SSE streams) are passed through as-is.
 */
async function handler(req: Request, ctx: RouteContext<"/bff/v1/[...path]">) {
  if (!csrfOk(req)) return problemResponse(403, "csrf", "Missing CSRF header");
  const { path } = await ctx.params;
  const url = new URL(req.url);
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const upstream = await fetch(`${API_URL}/v1/${path.map(encodeURIComponent).join("/")}${url.search}`, {
    method: req.method,
    headers: forwardHeaders(req, token),
    // A Blob, not an ArrayBuffer: fetch transfers (detaches) an ArrayBuffer on send, so a
    // retry on a stale keep-alive socket (e.g. after an API restart) would fail.
    body: req.method === "GET" || req.method === "HEAD" ? undefined : new Blob([await req.arrayBuffer()]),
    cache: "no-store",
    signal: req.signal,
  });
  const headers = new Headers();
  for (const k of ["content-type", "cache-control", "x-request-id", "www-authenticate"]) {
    const v = upstream.headers.get(k);
    if (v) headers.set(k, v);
  }
  if (headers.get("content-type")?.includes("text/event-stream") && upstream.body) {
    headers.set("cache-control", "no-cache, no-transform");
    headers.set("x-accel-buffering", "no");
    return new Response(endCleanlyOnDisconnect(upstream.body), { status: upstream.status, headers });
  }
  return new Response(upstream.body, { status: upstream.status, headers });
}

/**
 * Long-lived SSE streams outlive API restarts and deploys. When the upstream
 * connection drops, end the browser's stream normally (EventSource then
 * reconnects with backoff) instead of surfacing it as a proxy error.
 */
function endCleanlyOnDisconnect(body: ReadableStream<Uint8Array>) {
  const reader = body.getReader();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { value, done } = await reader.read();
        if (done) controller.close();
        else controller.enqueue(value);
      } catch {
        controller.close();
      }
    },
    cancel(reason) {
      return reader.cancel(reason).catch(() => {});
    },
  });
}

export { handler as GET, handler as POST, handler as PUT, handler as PATCH, handler as DELETE };
export const dynamic = "force-dynamic";

import { assertSafeUrl, networkError } from "../platform/outbound.js";

/**
 * A small MCP client for upstream servers over streamable HTTP (MCP-01). The
 * gateway speaks to upstreams with the credentials it holds; agents never see
 * them. Sessions are reused per server and re-established when the upstream
 * forgets them (HTTP 404). Responses may be JSON or an SSE stream; only the
 * response to our request is taken from a stream.
 */

export const PROTOCOL_VERSION = "2025-06-18";
const MAX_BYTES = 5 * 1024 * 1024;
const SESSION_TTL_MS = 10 * 60_000;

export class UpstreamError extends Error {
  constructor(
    message: string,
    readonly kind: "unreachable" | "http" | "protocol" | "timeout" | "rpc",
    readonly rpc?: { code: number; message: string; data?: unknown },
  ) {
    super(message);
  }
}

export type UpstreamConfig = { id: string; url: string; headers: Record<string, string>; allowPrivate: boolean; version: string };

type Session = { id: string | null; protocol: string; at: number; key: string };
const sessions = new Map<string, Session>();
let seq = 0;

async function readBody(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_BYTES) {
      await reader.cancel();
      throw new UpstreamError("The upstream response is too large (over 5 MB)", "protocol");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Finds the JSON-RPC response with our id in a JSON body or an SSE stream. */
export function pickResponse(contentType: string, text: string, id: number): { result?: unknown; error?: { code: number; message: string; data?: unknown } } {
  const candidates: unknown[] = [];
  if (contentType.includes("text/event-stream")) {
    for (const event of text.split(/\r?\n\r?\n/)) {
      const data = event
        .split(/\r?\n/)
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).replace(/^ /, ""))
        .join("\n");
      if (!data) continue;
      try {
        candidates.push(JSON.parse(data));
      } catch {
        // ignore non-JSON events
      }
    }
  } else {
    try {
      const v = JSON.parse(text);
      candidates.push(...(Array.isArray(v) ? v : [v]));
    } catch {
      throw new UpstreamError("The upstream didn't return JSON", "protocol");
    }
  }
  const hit = candidates.find((m) => m && typeof m === "object" && (m as { id?: unknown }).id === id) as { result?: unknown; error?: { code: number; message: string } } | undefined;
  if (!hit) throw new UpstreamError("The upstream didn't answer the request", "protocol");
  return hit;
}

async function post(cfg: UpstreamConfig, session: Session | null, message: Record<string, unknown>, timeoutMs: number): Promise<Response> {
  await assertSafeUrl(cfg.url, { allowPrivate: cfg.allowPrivate });
  try {
    return await fetch(cfg.url, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        ...cfg.headers,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "user-agent": `votal-nexus-mcp-gateway/${cfg.version}`,
        ...(session?.id ? { "mcp-session-id": session.id } : {}),
        ...(session ? { "mcp-protocol-version": session.protocol } : {}),
      },
      body: JSON.stringify(message),
    });
  } catch (e) {
    if ((e as Error).name === "TimeoutError") throw new UpstreamError(`The upstream didn't answer within ${timeoutMs / 1000}s`, "timeout");
    throw new UpstreamError(`Couldn't reach the upstream: ${networkError(e)}`, "unreachable");
  }
}

async function rpc(cfg: UpstreamConfig, session: Session | null, method: string, params: unknown, timeoutMs: number) {
  const id = ++seq;
  const res = await post(cfg, session, { jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) }, timeoutMs);
  if (res.status === 404 && session?.id) return { expired: true as const, res };
  if (res.status === 401 || res.status === 403) throw new UpstreamError(`The upstream refused the gateway's credentials (HTTP ${res.status})`, "http");
  if (!res.ok) throw new UpstreamError(`The upstream answered HTTP ${res.status}`, "http");
  const msg = pickResponse(res.headers.get("content-type") ?? "", await readBody(res), id);
  if (msg.error) throw new UpstreamError(msg.error.message || "The upstream returned an error", "rpc", msg.error);
  return { expired: false as const, res, result: msg.result };
}

async function connect(cfg: UpstreamConfig, key: string): Promise<Session & { info: unknown }> {
  const r = await rpc(cfg, null, "initialize", { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "votal-nexus-mcp-gateway", version: cfg.version } }, 20_000);
  if (r.expired) throw new UpstreamError("Unexpected 404 from initialize", "http");
  const result = r.result as { protocolVersion?: string; serverInfo?: unknown; capabilities?: { tools?: unknown } };
  const s: Session = { id: r.res.headers.get("mcp-session-id"), protocol: result?.protocolVersion ?? PROTOCOL_VERSION, at: Date.now(), key };
  // notifications/initialized: no id, no response body expected.
  const n = await post(cfg, s, { jsonrpc: "2.0", method: "notifications/initialized" }, 10_000);
  await n.body?.cancel();
  sessions.set(cfg.id, s);
  return { ...s, info: { serverInfo: result?.serverInfo ?? null, protocolVersion: s.protocol, capabilities: result?.capabilities ?? {} } };
}

const configKey = (cfg: UpstreamConfig) => `${cfg.url}\n${JSON.stringify(cfg.headers)}`;

/** Sends one request to the upstream, (re)establishing a session as needed. */
export async function request(cfg: UpstreamConfig, method: string, params: unknown, timeoutMs = 60_000): Promise<unknown> {
  const key = configKey(cfg);
  let s = sessions.get(cfg.id);
  if (!s || s.key !== key || Date.now() - s.at > SESSION_TTL_MS) s = await connect(cfg, key);
  let r = await rpc(cfg, s, method, params, timeoutMs);
  if (r.expired) {
    s = await connect(cfg, key);
    r = await rpc(cfg, s, method, params, timeoutMs);
    if (r.expired) throw new UpstreamError("The upstream keeps rejecting its session", "http");
  }
  return r.result;
}

/** A fresh connection: server info plus every tool (following pagination). */
export async function discover(cfg: UpstreamConfig) {
  sessions.delete(cfg.id);
  const s = await connect(cfg, configKey(cfg));
  const tools: { name: string; title?: string; description?: string; inputSchema?: unknown; annotations?: Record<string, unknown> }[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 50; page++) {
    const r = (await request(cfg, "tools/list", cursor ? { cursor } : {}, 30_000)) as { tools?: typeof tools; nextCursor?: string };
    tools.push(...(r?.tools ?? []));
    if (!r?.nextCursor || tools.length >= 1000) break;
    cursor = r.nextCursor;
  }
  return { info: s.info, tools: tools.filter((t) => typeof t?.name === "string" && t.name.length <= 128) };
}

export const forgetSession = (serverId: string) => sessions.delete(serverId);

import "server-only";

export const SESSION_COOKIE = "nexus_session";
export const API_URL = process.env.NEXUS_API_URL ?? "http://localhost:8080";

export const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/",
  maxAge: 12 * 60 * 60,
};

/** Headers every BFF → API call carries: the caller's real IP and user agent, for audit and risk signals. */
export function forwardHeaders(req: Request, token?: string) {
  const h = new Headers();
  h.set("content-type", req.headers.get("content-type") ?? "application/json");
  h.set("user-agent", req.headers.get("user-agent") ?? "");
  h.set("accept", req.headers.get("accept") ?? "application/json");
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? req.headers.get("x-real-ip");
  if (ip) h.set("x-forwarded-for", ip);
  h.set("nexus-client", "web");
  if (token) h.set("authorization", `Bearer ${token}`);
  return h;
}

/**
 * CSRF defence for cookie-authenticated mutations: SameSite=Lax already blocks
 * cross-site POSTs from carrying the cookie; requiring a custom header adds a
 * second layer, since browsers can't send it cross-origin without a preflight.
 */
export function csrfOk(req: Request) {
  if (req.method === "GET" || req.method === "HEAD") return true;
  return req.headers.get("x-nexus-csrf") === "1";
}

export const problemResponse = (status: number, code: string, title: string) =>
  Response.json({ type: "about:blank", status, code, title }, { status, headers: { "content-type": "application/problem+json" } });

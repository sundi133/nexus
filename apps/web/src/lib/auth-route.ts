import "server-only";
import { cookies } from "next/headers";
import { API_URL, cookieOptions, csrfOk, forwardHeaders, problemResponse, SESSION_COOKIE } from "./session";

/**
 * Calls an API auth endpoint, moves the returned token into the HttpOnly
 * cookie, and returns the rest of the payload to the browser.
 */
export async function exchangeForCookie(req: Request, apiPath: string) {
  if (!csrfOk(req)) return problemResponse(403, "csrf", "Missing CSRF header");
  const body = await req.json().catch(() => ({}));
  const upstream = await fetch(`${API_URL}${apiPath}`, {
    method: "POST",
    headers: forwardHeaders(req),
    body: JSON.stringify({ ...body, client: "web" }),
    cache: "no-store",
  });
  const data = await upstream.json();
  if (!upstream.ok) return Response.json(data, { status: upstream.status });
  const { token, ...rest } = data as { token: string };
  (await cookies()).set(SESSION_COOKIE, token, cookieOptions);
  return Response.json(rest, { status: upstream.status });
}

import { cookies } from "next/headers";
import { API_URL, csrfOk, forwardHeaders, problemResponse, SESSION_COOKIE } from "@/lib/session";

export async function POST(req: Request) {
  if (!csrfOk(req)) return problemResponse(403, "csrf", "Missing CSRF header");
  const jar = await cookies();
  const token = jar.get(SESSION_COOKIE)?.value;
  if (token) {
    await fetch(`${API_URL}/v1/auth/logout`, { method: "POST", headers: forwardHeaders(req, token) }).catch(() => {});
  }
  jar.delete(SESSION_COOKIE);
  return new Response(null, { status: 204 });
}

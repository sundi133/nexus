import { cookies } from "next/headers";
import { bindState } from "@/lib/federation";
import { API_URL, csrfOk, forwardHeaders, problemResponse, SESSION_COOKIE } from "@/lib/session";

/** An admin's test sign-in: same round trip as a real one, bound to this browser, but no session comes of it. */
export async function POST(req: Request) {
  if (!csrfOk(req)) return problemResponse(403, "csrf", "Missing CSRF header");
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) return problemResponse(401, "unauthenticated", "Sign in first");
  const { idp_id } = (await req.json().catch(() => ({}))) as { idp_id?: string };
  const res = await fetch(`${API_URL}/v1/identity-providers/${encodeURIComponent(idp_id ?? "")}/test`, { method: "POST", headers: forwardHeaders(req, token), body: "{}", cache: "no-store" });
  const data = await res.json();
  if (!res.ok) return Response.json(data, { status: res.status });
  await bindState(req, data.state);
  return Response.json({ redirect_url: data.redirect_url });
}

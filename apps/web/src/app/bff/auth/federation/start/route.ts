import { bindState } from "@/lib/federation";
import { API_URL, csrfOk, forwardHeaders, problemResponse } from "@/lib/session";

/** Starts a sign-in at the organization's IdP; the browser then goes to `redirect_url`. */
export async function POST(req: Request) {
  if (!csrfOk(req)) return problemResponse(403, "csrf", "Missing CSRF header");
  const { email, next } = (await req.json().catch(() => ({}))) as { email?: string; next?: string };
  const res = await fetch(`${API_URL}/v1/auth/federation/start`, { method: "POST", headers: forwardHeaders(req), body: JSON.stringify({ email, return_to: next, client: "web" }), cache: "no-store" });
  const data = await res.json();
  if (!res.ok) return Response.json(data, { status: res.status });
  await bindState(req, data.state);
  return Response.json({ redirect_url: data.redirect_url });
}

import { API_URL, csrfOk, forwardHeaders, problemResponse } from "@/lib/session";

/** Does this email sign in through an IdP? (home-realm discovery) */
export async function POST(req: Request) {
  if (!csrfOk(req)) return problemResponse(403, "csrf", "Missing CSRF header");
  const res = await fetch(`${API_URL}/v1/auth/federation/discover`, { method: "POST", headers: forwardHeaders(req), body: await req.text(), cache: "no-store" });
  return Response.json(await res.json(), { status: res.status });
}

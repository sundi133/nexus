import { cookies } from "next/headers";
import { API_URL, forwardHeaders, SESSION_COOKIE } from "@/lib/session";

/**
 * OIDC authorization endpoint on the console's origin, so the user's existing
 * Nexus session (HttpOnly cookie) applies. The API makes the decision; this
 * handler only turns it into a browser redirect.
 */
export async function GET(req: Request, ctx: RouteContext<"/oidc/[slug]/authorize">) {
  const { slug } = await ctx.params;
  const url = new URL(req.url);
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const res = await fetch(`${API_URL}/v1/sso/oidc/${encodeURIComponent(slug)}/authorize${url.search}`, {
    headers: forwardHeaders(req, token),
    cache: "no-store",
  });
  const origin = url.origin;
  if (!res.ok) return Response.redirect(`${origin}/sso/error?title=${encodeURIComponent("Sign-in unavailable")}`, 302);
  const d = (await res.json()) as { action: "redirect"; location: string } | { action: "login" } | { action: "error"; title: string; message: string };

  if (d.action === "redirect") return Response.redirect(d.location, 302);
  if (d.action === "login") {
    // Come back here after signing in; drop prompt=login so the fresh sign-in satisfies it.
    const back = new URL(url);
    back.searchParams.delete("prompt");
    return Response.redirect(`${origin}/login?next=${encodeURIComponent(back.pathname + back.search)}`, 302);
  }
  return Response.redirect(`${origin}/sso/error?title=${encodeURIComponent(d.title)}&message=${encodeURIComponent(d.message)}`, 302);
}

export const dynamic = "force-dynamic";

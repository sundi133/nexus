import { API_URL } from "@/lib/session";

/**
 * Discovery, JWKS, token and userinfo: server-to-server or SPA calls that carry
 * their own credentials. Passed through to the API untouched (no cookies).
 */
async function handler(req: Request, ctx: RouteContext<"/oidc/[slug]/[...rest]">) {
  const { slug, rest } = await ctx.params;
  const url = new URL(req.url);
  const headers = new Headers();
  for (const k of ["authorization", "content-type", "accept", "user-agent"]) {
    const v = req.headers.get(k);
    if (v) headers.set(k, v);
  }
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (ip) headers.set("x-forwarded-for", ip);
  const upstream = await fetch(`${API_URL}/oidc/${encodeURIComponent(slug)}/${rest.map(encodeURIComponent).join("/")}${url.search}`, {
    method: req.method,
    headers,
    body: req.method === "GET" || req.method === "HEAD" ? undefined : await req.arrayBuffer(),
    cache: "no-store",
  });
  const out = new Headers();
  for (const k of ["content-type", "cache-control", "pragma", "www-authenticate", "access-control-allow-origin"]) {
    const v = upstream.headers.get(k);
    if (v) out.set(k, v);
  }
  return new Response(upstream.body, { status: upstream.status, headers: out });
}

export { handler as GET, handler as POST };
export const OPTIONS = () =>
  new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "Authorization, Content-Type",
      "access-control-allow-methods": "GET, POST",
      "access-control-max-age": "600",
    },
  });
export const dynamic = "force-dynamic";

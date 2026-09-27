import { API_URL } from "@/lib/session";

export async function GET(_req: Request, ctx: RouteContext<"/saml/[slug]/metadata">) {
  const { slug } = await ctx.params;
  const upstream = await fetch(`${API_URL}/saml/${encodeURIComponent(slug)}/metadata`, { cache: "no-store" });
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { "content-type": upstream.headers.get("content-type") ?? "application/xml", "cache-control": "public, max-age=300" },
  });
}

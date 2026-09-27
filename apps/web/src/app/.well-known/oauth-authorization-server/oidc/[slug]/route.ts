import { API_URL } from "@/lib/session";

/**
 * RFC 8414 discovery with the issuer's path inserted after /.well-known/, which is where MCP
 * clients (Cursor, Claude Desktop, VS Code) look first for the issuer {origin}/oidc/{slug}. The
 * same document as {issuer}/.well-known/openid-configuration.
 */
export async function GET(_req: Request, ctx: { params: Promise<{ slug: string }> }) {
  const { slug } = await ctx.params;
  const upstream = await fetch(`${API_URL}/oidc/${encodeURIComponent(slug)}/.well-known/oauth-authorization-server`, { cache: "no-store" });
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { "content-type": upstream.headers.get("content-type") ?? "application/json", "cache-control": "public, max-age=300", "access-control-allow-origin": "*" },
  });
}

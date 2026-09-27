import { API_URL } from "@/lib/session";

/** Our SAML service provider metadata, at the entity ID's address, for the IdP admin to import. */
export async function GET(_req: Request, ctx: { params: Promise<{ slug: string }> }) {
  const { slug } = await ctx.params;
  const res = await fetch(`${API_URL}/v1/federation/saml/${encodeURIComponent(slug)}/metadata`, { cache: "no-store" });
  return new Response(await res.text(), { status: res.status, headers: { "content-type": res.headers.get("content-type") ?? "application/xml" } });
}

export const dynamic = "force-dynamic";

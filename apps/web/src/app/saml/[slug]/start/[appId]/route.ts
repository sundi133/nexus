import { samlDecision } from "@/lib/saml-web";

/** IdP-initiated sign-in (the app launcher tile for SAML apps). */
export async function GET(req: Request, ctx: RouteContext<"/saml/[slug]/start/[appId]">) {
  const { slug, appId } = await ctx.params;
  const relay = new URL(req.url).searchParams.get("RelayState");
  const q = relay ? `?RelayState=${encodeURIComponent(relay)}` : "";
  return samlDecision(req, `/v1/sso/saml/${encodeURIComponent(slug)}/start/${encodeURIComponent(appId)}${q}`, `/saml/${slug}/start/${appId}${q}`);
}

export const dynamic = "force-dynamic";

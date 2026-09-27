import { samlDecision } from "@/lib/saml-web";

/**
 * SAML SSO endpoint on the console origin (so the Nexus session applies).
 * GET = HTTP-Redirect binding (deflated request), POST = HTTP-POST binding.
 * After a login detour the request comes back as GET with binding=post preserved.
 */
async function handle(req: Request, slug: string, samlRequest: string | null, relayState: string | null, binding: "redirect" | "post") {
  const origin = new URL(req.url).origin;
  if (!samlRequest) return Response.redirect(`${origin}/sso/error?title=${encodeURIComponent("Missing SAML request")}`, 302);
  const q = new URLSearchParams({ SAMLRequest: samlRequest, binding });
  if (relayState) q.set("RelayState", relayState);
  return samlDecision(req, `/v1/sso/saml/${encodeURIComponent(slug)}/sso?${q}`, `/saml/${slug}/sso?${q}`);
}

export async function GET(req: Request, ctx: RouteContext<"/saml/[slug]/sso">) {
  const { slug } = await ctx.params;
  const u = new URL(req.url);
  const binding = u.searchParams.get("binding") === "post" ? "post" : "redirect";
  return handle(req, slug, u.searchParams.get("SAMLRequest"), u.searchParams.get("RelayState"), binding);
}

export async function POST(req: Request, ctx: RouteContext<"/saml/[slug]/sso">) {
  const { slug } = await ctx.params;
  const form = await req.formData();
  return handle(req, slug, form.get("SAMLRequest")?.toString() ?? null, form.get("RelayState")?.toString() ?? null, "post");
}

export const dynamic = "force-dynamic";

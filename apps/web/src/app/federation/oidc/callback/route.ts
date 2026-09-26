import { finishFederation } from "@/lib/federation";

/** OpenID Connect redirect URI: the IdP sends the browser back here with ?code&state (or ?error). */
export async function GET(req: Request) {
  const q = new URL(req.url).searchParams;
  return finishFederation(req, { state: q.get("state"), code: q.get("code"), error: q.get("error"), error_description: q.get("error_description") });
}

export const dynamic = "force-dynamic";

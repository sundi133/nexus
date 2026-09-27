import { finishFederation } from "@/lib/federation";

/** SAML assertion consumer service (HTTP-POST binding). */
export async function POST(req: Request) {
  const form = await req.formData();
  return finishFederation(req, { state: form.get("RelayState")?.toString(), saml_response: form.get("SAMLResponse")?.toString() });
}

export const dynamic = "force-dynamic";

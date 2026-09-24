import "server-only";
import { cookies } from "next/headers";
import { API_URL, forwardHeaders, SESSION_COOKIE } from "./session";

type Decision =
  | { action: "post"; acs_url: string; saml_response: string; relay_state: string | null }
  | { action: "login"; reason: string }
  | { action: "error"; title: string; message: string };

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** HTTP-POST binding: a self-submitting form that delivers the signed response to the app. */
function autoPost(d: Extract<Decision, { action: "post" }>) {
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Signing you in…</title>
<meta name="referrer" content="no-referrer">
<style>body{font:14px system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;color:#5b606b;background:#f7f7f8}</style></head>
<body><form method="post" action="${esc(d.acs_url)}">
<input type="hidden" name="SAMLResponse" value="${esc(d.saml_response)}">
${d.relay_state ? `<input type="hidden" name="RelayState" value="${esc(d.relay_state)}">` : ""}
<noscript><button type="submit">Continue to the app</button></noscript>
</form><p>Signing you in…</p>
<script>document.forms[0].submit()</script></body></html>`;
  return new Response(html, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY" },
  });
}

/** Asks the API for a SAML decision with the user's session, then renders it for the browser. */
export async function samlDecision(req: Request, apiPath: string, loginNext: string) {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  const origin = new URL(req.url).origin;
  const res = await fetch(`${API_URL}${apiPath}`, { headers: forwardHeaders(req, token), cache: "no-store" });
  if (!res.ok) return Response.redirect(`${origin}/sso/error?title=${encodeURIComponent("Sign-in unavailable")}`, 302);
  const d = (await res.json()) as Decision;
  if (d.action === "post") return autoPost(d);
  if (d.action === "login") return Response.redirect(`${origin}/login?next=${encodeURIComponent(loginNext)}`, 302);
  return Response.redirect(`${origin}/sso/error?title=${encodeURIComponent(d.title)}&message=${encodeURIComponent(d.message)}`, 302);
}

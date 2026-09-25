import "server-only";
import { cookies } from "next/headers";
import { API_URL, cookieOptions, forwardHeaders, SESSION_COOKIE } from "./session";

/**
 * Sign-in through the organization's IdP (AUTH-10), browser side. The API
 * returns a `state`; we pin it to this browser in a short-lived cookie, so an
 * IdP answer only completes a sign-in the same browser started (no login CSRF).
 */

export const FED_COOKIE = "nexus_fed_state";

/**
 * SAML answers arrive as a cross-site POST, so the cookie must be SameSite=None
 * (which requires Secure). Browsers accept Secure cookies on https and on
 * localhost; anywhere else (plain http on a LAN address) fall back to Lax,
 * where OIDC still works but SAML can't.
 */
export async function bindState(req: Request, state: string) {
  const u = new URL(req.url);
  // Production is always https (behind a proxy req.url may still say http).
  const secureContext = process.env.NODE_ENV === "production" || u.protocol === "https:" || u.hostname === "localhost" || u.hostname === "127.0.0.1";
  (await cookies()).set(FED_COOKIE, state, {
    httpOnly: true,
    secure: secureContext,
    sameSite: secureContext ? "none" : "lax",
    path: "/federation",
    maxAge: 10 * 60,
  });
}

const safe = (p: string) => (p.startsWith("/") && !p.startsWith("//") && !p.startsWith("/\\") ? p : "/");
const loginError = (origin: string, message: string) => Response.redirect(`${origin}/login?${new URLSearchParams({ sso_error: message })}`, 303);

export async function finishFederation(req: Request, input: { state?: string | null; code?: string | null; saml_response?: string | null; error?: string | null; error_description?: string | null }) {
  const origin = new URL(req.url).origin;
  const jar = await cookies();
  const bound = jar.get(FED_COOKIE)?.value;
  jar.delete({ name: FED_COOKIE, path: "/federation" });
  if (!input.state || !bound || bound !== input.state) return loginError(origin, "This sign-in didn't start in this browser, or took too long. Please try again.");

  const body = Object.fromEntries(Object.entries(input).filter(([, v]) => v));
  const headers = forwardHeaders(req);
  headers.set("content-type", "application/json"); // the IdP posted a form; we send JSON
  const res = await fetch(`${API_URL}/v1/auth/federation/complete`, { method: "POST", headers, body: JSON.stringify({ ...body, client: "web" }), cache: "no-store" });
  const data = (await res.json().catch(() => ({}))) as Record<string, any>;
  if (!res.ok) return loginError(origin, data.title ?? "Single sign-on failed");
  if (data.purpose === "test") return Response.redirect(`${origin}/settings/identity-providers?${new URLSearchParams({ idp: data.idp_id, test: data.state })}`, 303);

  jar.set(SESSION_COOKIE, data.token, cookieOptions);
  const next = safe(data.return_to ?? "/");
  const to =
    data.session.state === "enroll_mfa"
      ? `/setup-mfa?next=${encodeURIComponent(next)}`
      : data.session.state === "pending_mfa"
        ? `/login?step=mfa&next=${encodeURIComponent(next)}`
        : next;
  return Response.redirect(`${origin}${to}`, 303);
}

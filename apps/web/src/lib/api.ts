"use client";

import { ApiProblem, createClient, unwrap } from "@nexus/api-client";

/**
 * Browser-side client. Calls go to the BFF (/bff/v1/*), which attaches the
 * session token from the HttpOnly cookie. Same generated client as mobile.
 */
export const api = createClient({
  baseUrl: "/bff",
  fetch: (input, init) => {
    const req = new Request(input, init);
    req.headers.set("x-nexus-csrf", "1");
    return fetch(req);
  },
});

export { ApiProblem, unwrap };

/** POST to a BFF auth endpoint (these set/clear the session cookie). */
export async function bffAuth<T>(path: "login" | "signup" | "logout" | "accept-invite" | "passkey", body?: unknown): Promise<T> {
  const res = await fetch(`/bff/auth/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-nexus-csrf": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json();
  if (!res.ok) throw new ApiProblem(res.status, data);
  return data as T;
}

/** Field-level errors from a 400 problem, keyed by field path. */
export function fieldErrors(err: unknown): Record<string, string> {
  if (!(err instanceof ApiProblem) || !err.problem.errors) return {};
  return Object.fromEntries(err.problem.errors.map((e) => [e.path, e.message]));
}

export type SignInResult = {
  session: { state: "pending_mfa" | "enroll_mfa" | "active" };
  mfa: { required: boolean; enrollment_required: boolean; factors: ("totp" | "push" | "webauthn")[] };
};

/** Protocol endpoints (OIDC/SAML) are route handlers, not pages: they need a full browser navigation. */
export function goTo(url: string, router: { replace: (u: string) => void }) {
  if (url.startsWith("/oidc/") || url.startsWith("/saml/")) window.location.assign(url);
  else router.replace(url);
}

/** Where to send the user after a sign-in step, based on the session state. */
export function nextStepUrl(r: SignInResult, next: string) {
  const safeNext = next.startsWith("/") && !next.startsWith("//") ? next : "/";
  if (r.session.state === "enroll_mfa") return `/setup-mfa?next=${encodeURIComponent(safeNext)}`;
  if (r.session.state === "pending_mfa") return `/login?step=mfa&next=${encodeURIComponent(safeNext)}`;
  return safeNext;
}

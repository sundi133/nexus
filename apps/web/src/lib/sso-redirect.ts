import "server-only";

/** Decisions the API returns for a sign-in to an app that need the browser to do something first. */
export type Interaction =
  | { action: "login"; reason?: string }
  | { action: "device_check"; reason: string; app_name: string }
  | { action: "mfa"; reason: string; app_name: string }
  | { action: "error"; code?: string; title: string; message: string; app_name?: string | null };

/**
 * Turns an interaction into a redirect to the console page that handles it.
 * `next` is the protocol URL to come back to (same origin, path only).
 */
export function interactionRedirect(origin: string, d: Interaction, next: string) {
  const q = (params: Record<string, string | null | undefined>) =>
    new URLSearchParams(Object.entries(params).filter((e): e is [string, string] => !!e[1])).toString();
  switch (d.action) {
    case "login":
      return Response.redirect(`${origin}/login?${q({ next })}`, 302);
    case "device_check":
      return Response.redirect(`${origin}/sso/device-check?${q({ next, app: d.app_name, reason: d.reason })}`, 302);
    case "mfa":
      return Response.redirect(`${origin}/sso/verify?${q({ next, app: d.app_name })}`, 302);
    case "error":
      return Response.redirect(`${origin}/sso/error?${q({ code: d.code, title: d.title, message: d.message })}`, 302);
  }
}

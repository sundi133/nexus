import { sql } from "kysely";
import type { Deps } from "../context.js";
import { domainOf } from "../org/domains.js";
import { ApiError } from "../platform/errors.js";

/**
 * Home-realm discovery and the "sign in with your IdP" rule, kept free of the
 * sign-in routes so both sides can use it without an import cycle.
 */

/** Which IdP (if any) signs in this email's domain. Only domains the organization has verified. */
export async function idpForEmail(deps: Deps, email: string) {
  return deps.db.unscoped(
    async (tx) => (await sql<{ org_id: string; idp_id: string; name: string; required: boolean }>`SELECT * FROM nexus_federation_for_domain(${domainOf(email)})`.execute(tx)).rows[0],
  );
}

/**
 * Whether this person must sign in through their IdP rather than with a
 * password or passkey. Break-glass accounts never are: they exist for the
 * day the IdP is down.
 */
export async function federationRequiredFor(deps: Deps, email: string, user?: { user_id: string; org_id: string }) {
  const idp = await idpForEmail(deps, email);
  if (!idp?.required) return null;
  if (user && user.org_id === idp.org_id) {
    const bg = await deps.db.tenant(user.org_id, (tx) => tx.selectFrom("users").select("break_glass").where("id", "=", user.user_id).executeTakeFirst());
    if (bg?.break_glass) return null;
  }
  return idp;
}

/** People in a domain whose IdP is required sign in there, not here (break-glass accounts excepted). */
export async function refuseIfFederationRequired(deps: Deps, email: string, user?: { user_id: string; org_id: string }) {
  const idp = await federationRequiredFor(deps, email, user);
  if (idp) throw new ApiError(403, "use_sso", `Sign in with ${idp.name}`, { provider: { name: idp.name } });
}

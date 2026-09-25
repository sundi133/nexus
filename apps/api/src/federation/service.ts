import { randomUUID } from "node:crypto";
import { sql } from "kysely";
import type { Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { createSession, verifiedFactorTypes, type MfaMethod } from "../auth/routes.js";
import { alertIfBreakGlass } from "../directory/break-glass.js";
import { getSettings, mfaRequired } from "../org/settings.js";
import { domainOf } from "../org/domains.js";
import type { Tx } from "../platform/db.js";
import type { SessionState } from "../platform/db-types.js";
import { newId } from "../platform/ids.js";
import { touchUsers } from "../provisioning/service.js";
import { authorizeUrl, discover, exchangeCode, FederationError, pkce, randomToken, type FederatedClaims } from "./oidc-rp.js";
import { authnRequestUrl, newRequestId, verifySamlResponse } from "./saml-sp.js";

/**
 * Sign-in through the organization's own IdP (AUTH-10): start (redirect to
 * the IdP), complete (verify what comes back, find or create the account,
 * open a session), and the rule that keeps passwords out of federated domains.
 */

const REQUEST_TTL_MS = 10 * 60_000;
export const secretAad = (id: string) => `identity_provider:${id}`;

/** Where the IdP sends people back: on the console origin, which holds the session cookie. */
export function spEndpoints(deps: Deps, orgSlug: string) {
  return {
    oidc_redirect_uri: `${deps.cfg.publicUrl}/federation/oidc/callback`,
    saml_acs_url: `${deps.cfg.publicUrl}/federation/saml/acs`,
    saml_entity_id: `${deps.cfg.publicUrl}/federation/saml/${orgSlug}`,
    saml_metadata_url: `${deps.cfg.publicUrl}/federation/saml/${orgSlug}/metadata`,
  };
}

const safeReturnTo = (r: string | undefined) => (r && r.startsWith("/") && !r.startsWith("//") && !r.startsWith("/\\") ? r.slice(0, 500) : "/");

export async function startFederation(
  deps: Deps,
  a: { orgId: string; idpId: string; purpose: "login" | "test"; returnTo?: string; client?: string; loginHint?: string; requestedBy?: string },
): Promise<{ redirect_url: string; state: string }> {
  const { idp, slug } = await deps.db.tenant(a.orgId, async (tx) => {
    await tx.deleteFrom("federation_requests").where("expires_at", "<", new Date(Date.now() - 86_400_000)).execute();
    const idp = await tx.selectFrom("identity_providers").selectAll().where("id", "=", a.idpId).executeTakeFirst();
    const org = await tx.selectFrom("organizations").select("slug").where("id", "=", a.orgId).executeTakeFirstOrThrow();
    return { idp, slug: org.slug };
  });
  if (!idp || (!idp.enabled && a.purpose === "login")) throw new FederationError("idp_disabled", "Single sign-on isn't available for this organization right now");
  const ep = spEndpoints(deps, slug);
  const state = randomUUID();
  let url: string;
  let rec: { nonce?: string; code_verifier?: string; saml_request_id?: string };
  if (idp.protocol === "oidc") {
    const d = await discover(idp.issuer!, deps.cfg.allowPrivateOutbound);
    const p = pkce();
    const nonce = randomToken();
    url = authorizeUrl(d, { clientId: idp.client_id!, redirectUri: ep.oidc_redirect_uri, scopes: idp.scopes, state, nonce, codeChallenge: p.challenge, loginHint: a.loginHint });
    rec = { nonce, code_verifier: p.verifier };
  } else {
    const requestId = newRequestId();
    url = authnRequestUrl({ ssoUrl: idp.idp_sso_url!, spEntityId: ep.saml_entity_id, acsUrl: ep.saml_acs_url, requestId, relayState: state, loginHint: a.loginHint });
    rec = { saml_request_id: requestId };
  }
  await deps.db.tenant(a.orgId, (tx) =>
    tx
      .insertInto("federation_requests")
      .values({
        id: state,
        org_id: a.orgId,
        idp_id: idp.id,
        purpose: a.purpose,
        return_to: safeReturnTo(a.returnTo),
        client: a.client ?? "web",
        requested_by: a.requestedBy ?? null,
        expires_at: new Date(Date.now() + REQUEST_TTL_MS),
        ...rec,
      })
      .execute(),
  );
  return { redirect_url: url, state };
}

export type CompleteInput = { state: string; code?: string; saml_response?: string; error?: string; error_description?: string };
export type LoginOutcome = {
  purpose: "login";
  token: string;
  session: { id: string; state: SessionState; expires_at: Date };
  factors: string[];
  return_to: string;
};
export type TestOutcome = { purpose: "test"; idp_id: string; state: string };

export async function completeFederation(deps: Deps, meta: RequestMeta, input: CompleteInput): Promise<LoginOutcome | TestOutcome> {
  const orgId = await deps.db.unscoped(async (tx) => (await sql<{ o: string | null }>`SELECT nexus_federation_request_org(${input.state}::uuid) AS o`.execute(tx)).rows[0]?.o);
  if (!orgId) throw new FederationError("expired_request", "This sign-in has expired or was already used. Start again.");
  // Single use: claim the request before anything else.
  const claimed = await deps.db.tenant(orgId, async (tx) => {
    const req = await tx.updateTable("federation_requests").set({ used_at: new Date() }).where("id", "=", input.state).where("used_at", "is", null).returningAll().executeTakeFirst();
    if (!req) return null;
    const idp = await tx.selectFrom("identity_providers").selectAll().where("id", "=", req.idp_id).executeTakeFirstOrThrow();
    const org = await tx.selectFrom("organizations").select("slug").where("id", "=", orgId).executeTakeFirstOrThrow();
    return { req, idp, slug: org.slug };
  });
  if (!claimed) throw new FederationError("expired_request", "This sign-in has expired or was already used. Start again.");
  const { req, idp, slug } = claimed;
  const ep = spEndpoints(deps, slug);

  let claims: FederatedClaims;
  try {
    if (input.error) throw new FederationError("idp_rejected", `${idp.name} didn't sign you in: ${input.error_description || input.error}`);
    if (idp.protocol === "oidc") {
      if (!input.code) throw new FederationError("invalid_response", "The IdP didn't send a sign-in code");
      const d = await discover(idp.issuer!, deps.cfg.allowPrivateOutbound);
      claims = await exchangeCode(d, {
        clientId: idp.client_id!,
        clientSecret: deps.sealer.open(idp.client_secret!, secretAad(idp.id)).toString(),
        code: input.code,
        codeVerifier: req.code_verifier,
        redirectUri: ep.oidc_redirect_uri,
        nonce: req.nonce,
      });
    } else {
      if (!input.saml_response) throw new FederationError("invalid_response", "The IdP didn't send a SAML response");
      claims = verifySamlResponse(input.saml_response, {
        certs: idp.idp_certs,
        idpEntityId: idp.idp_entity_id!,
        spEntityId: ep.saml_entity_id,
        acsUrl: ep.saml_acs_url,
        requestId: req.saml_request_id,
        emailAttribute: idp.email_attribute || undefined,
      });
    }
    // An IdP may only vouch for people in the domains it was set up for, and only once they're verified.
    const domain = domainOf(claims.email);
    const verified = await deps.db.tenant(orgId, (tx) => tx.selectFrom("org_domains").select("id").where("domain", "=", domain).where("status", "in", ["verified", "failing"]).executeTakeFirst());
    if (!idp.domains.includes(domain) || !verified) {
      throw new FederationError("domain_not_allowed", `${idp.name} signed in ${claims.email}, but ${domain} isn't one of its verified domains in Nexus`);
    }
  } catch (err) {
    const e = err instanceof FederationError ? err : new FederationError("idp_error", (err as Error).message);
    await deps.db.tenant(orgId, async (tx) => {
      if (req.purpose === "test") {
        await tx.updateTable("federation_requests").set({ result: JSON.stringify({ ok: false, code: e.code, error: e.message }) }).where("id", "=", req.id).execute();
      } else {
        await audit(tx, orgId, { meta }, { type: "auth.login", outcome: "failure", actor: { type: "system", id: null, display: idp.name }, details: { method: "federation", idp: idp.name, reason: e.code, error: e.message } });
      }
    });
    if (req.purpose === "test") return { purpose: "test", idp_id: idp.id, state: req.id };
    throw e;
  }

  if (req.purpose === "test") {
    await deps.db.tenant(orgId, async (tx) => {
      const match = await findAccount(tx, idp.id, claims);
      const result = {
        ok: true,
        claims: { subject: claims.subject, email: claims.email, given_name: claims.givenName, family_name: claims.familyName, groups: claims.groups.slice(0, 50), mfa: claims.mfa },
        raw: claims.raw,
        account: match
          ? { outcome: match.user.status === "active" || match.user.status === "staged" ? "signs_in" : "refused", email: match.user.email, status: match.user.status, linked: match.linked }
          : { outcome: idp.jit_provisioning ? "created" : "refused", email: claims.email, status: null, linked: false },
        session_mfa: idp.mfa === "always" || (idp.mfa === "when_signalled" && claims.mfa) ? "satisfied_by_idp" : "nexus_mfa",
      };
      await tx.updateTable("federation_requests").set({ result: JSON.stringify(result) }).where("id", "=", req.id).execute();
      await tx.updateTable("identity_providers").set({ last_test_ok_at: new Date() }).where("id", "=", idp.id).execute();
      const tester = req.requested_by ? await tx.selectFrom("users").select("email").where("id", "=", req.requested_by).executeTakeFirst() : undefined;
      await audit(tx, orgId, { meta }, { type: "federation.tested", actor: req.requested_by ? { type: "user", id: req.requested_by, display: tester?.email } : undefined, target: { type: "identity_provider", id: idp.id, display: idp.name }, details: { email: claims.email, mfa: claims.mfa } });
    });
    return { purpose: "test", idp_id: idp.id, state: req.id };
  }

  return deps.db.tenant(orgId, async (tx) => {
    const actorFor = (id: string | null) => ({ type: "user" as const, id, display: claims.email });
    const refuse = async (code: string, message: string, userId: string | null) => {
      await audit(tx, orgId, { meta, display: claims.email }, { type: "auth.login", outcome: "denied", actor: actorFor(userId), details: { method: "federation", idp: idp.name, reason: code } });
      return new FederationError(code, message);
    };

    let found = await findAccount(tx, idp.id, claims);
    if (!found) {
      const elsewhere = await sql<{ t: boolean }>`SELECT nexus_email_taken(${claims.email}) AS t`.execute(tx);
      if (elsewhere.rows[0]?.t) throw await refuse("email_in_other_org", `${claims.email} already has a Nexus account in another organization`, null);
      if (!idp.jit_provisioning) throw await refuse("no_account", `There's no Nexus account for ${claims.email} yet. Ask your administrator to add you.`, null);
      const id = newId();
      await tx
        .insertInto("users")
        .values({ id, org_id: orgId, email: claims.email, given_name: claims.givenName.slice(0, 100), family_name: claims.familyName.slice(0, 100), status: "active", password_hash: null, attributes: "{}", updated_at: new Date() })
        .execute();
      await audit(tx, orgId, { meta, display: idp.name }, { type: "user.created", actor: { type: "system", id: null, display: idp.name }, target: { type: "user", id, display: claims.email }, details: { via: "federation", idp: idp.name } });
      await touchUsers(tx, orgId, [id]);
      found = { user: { id, email: claims.email, status: "active", given_name: claims.givenName, family_name: claims.familyName }, linked: false };
    }
    const u = found.user;
    if (u.status === "suspended" || u.status === "deprovisioned") throw await refuse("account_inactive", "This account is not active. Contact your administrator.", u.id);
    if (!found.linked) {
      await tx.insertInto("federated_identities").values({ id: newId(), org_id: orgId, idp_id: idp.id, subject: claims.subject, user_id: u.id }).onConflict((oc) => oc.columns(["idp_id", "user_id"]).doUpdateSet({ subject: claims.subject })).execute();
    }
    const fill: Record<string, unknown> = {};
    if (u.status === "staged") fill.status = "active"; // an invitation, answered by signing in with the IdP
    if (!u.given_name && claims.givenName) fill.given_name = claims.givenName.slice(0, 100);
    if (!u.family_name && claims.familyName) fill.family_name = claims.familyName.slice(0, 100);
    if (Object.keys(fill).length) {
      await tx.updateTable("users").set({ ...fill, updated_at: new Date() }).where("id", "=", u.id).execute();
      if (fill.status) await touchUsers(tx, orgId, [u.id]);
    }

    const settings = await getSettings(tx, orgId);
    const trustIdp = idp.mfa === "always" || (idp.mfa === "when_signalled" && claims.mfa);
    const factors = await verifiedFactorTypes(tx, u.id);
    const isAdmin = !!(await tx.selectFrom("user_roles").select("role").where("user_id", "=", u.id).executeTakeFirst());
    const state: SessionState = trustIdp ? "active" : factors.length ? "pending_mfa" : mfaRequired(settings, isAdmin) ? "enroll_mfa" : "active";
    const s = await createSession(tx, deps, meta, {
      orgId,
      userId: u.id,
      state,
      client: req.client,
      activeTtlMs: settings.session_ttl_hours * 3600_000,
      mfaMethod: trustIdp ? ("idp" satisfies MfaMethod) : undefined,
    });
    const now = new Date();
    if (state === "active") await tx.updateTable("users").set({ last_login_at: now }).where("id", "=", u.id).execute();
    await tx.updateTable("federated_identities").set({ last_login_at: now }).where("idp_id", "=", idp.id).where("user_id", "=", u.id).execute();
    await tx.updateTable("identity_providers").set({ last_login_at: now }).where("id", "=", idp.id).execute();
    await alertIfBreakGlass(tx, orgId, u.id, meta, idp.name);
    await audit(tx, orgId, { meta, display: claims.email }, {
      type: "auth.login",
      actor: actorFor(u.id),
      sessionId: s.session.id,
      details: { method: "federation", idp: idp.name, client: req.client, mfa: trustIdp ? "idp" : { pending_mfa: "pending", enroll_mfa: "enrollment_required", active: "not_enrolled" }[state] },
    });
    return { purpose: "login" as const, token: s.token, session: { id: s.session.id, state, expires_at: s.session.expires_at }, factors, return_to: req.return_to };
  });
}

type Account = { user: { id: string; email: string; status: string; given_name: string; family_name: string }; linked: boolean };

/** The account this IdP identity belongs to: by the IdP's stable subject first, then by email. */
async function findAccount(tx: Tx, idpId: string, claims: FederatedClaims): Promise<Account | null> {
  const cols = ["users.id", "users.email", "users.status", "users.given_name", "users.family_name"] as const;
  const linked = await tx
    .selectFrom("federated_identities")
    .innerJoin("users", "users.id", "federated_identities.user_id")
    .select(cols)
    .where("federated_identities.idp_id", "=", idpId)
    .where("federated_identities.subject", "=", claims.subject)
    .executeTakeFirst();
  if (linked) return { user: linked, linked: true };
  const byEmail = await tx.selectFrom("users").select(cols).where(sql`lower(email)`, "=", claims.email).where("status", "<>", "deprovisioned").executeTakeFirst();
  return byEmail ? { user: byEmail, linked: false } : null;
}

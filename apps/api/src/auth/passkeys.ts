import { alertIfBreakGlass } from "../directory/break-glass.js";
import { createRoute, z } from "@hono/zod-openapi";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { sql } from "kysely";
import { randomUUID } from "node:crypto";
import type { App, Deps, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { notifyUsers } from "../notify/send.js";
import { getSettings } from "../org/settings.js";
import type { Tx } from "../platform/db.js";
import { ApiError, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Factor, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { requireSession } from "./guard.js";
import { RateLimiter } from "./ratelimit.js";
import { createSession, markFreshMfa } from "./routes.js";
import { refuseIfFederationRequired } from "../federation/enforce.js";

/**
 * Passkeys (WebAuthn, SPEC AUTH-03/05). Phishing-resistant: the browser binds
 * each signature to our origin, so a look-alike site can't replay it. A
 * user-verified passkey counts as MFA on its own.
 */

const CHALLENGE_TTL_MS = 5 * 60_000;
const passkeyLimiter = new RateLimiter(20, 5 * 60_000);

const Options = z.record(z.string(), z.unknown()).openapi({ description: "Pass to @simplewebauthn/browser (startRegistration / startAuthentication)" });
const Ceremony = z.object({ challenge_id: Id, options: Options }).openapi("WebAuthnCeremony");
const CredentialResponse = z.record(z.string(), z.unknown()).openapi({ description: "The JSON returned by @simplewebauthn/browser" });

async function storeChallenge(tx: Tx, orgId: string, userId: string, purpose: "webauthn_register" | "webauthn_authenticate", challenge: string) {
  const id = newId();
  await tx
    .insertInto("auth_challenges")
    .values({ id, org_id: orgId, user_id: userId, purpose, challenge, expires_at: new Date(Date.now() + CHALLENGE_TTL_MS) })
    .execute();
  return id;
}

/** Single use: the challenge is deleted as it is read. */
async function takeChallenge(tx: Tx, id: string, userId: string, purpose: "webauthn_register" | "webauthn_authenticate") {
  const row = await tx
    .deleteFrom("auth_challenges")
    .where("id", "=", id)
    .where("user_id", "=", userId)
    .where("purpose", "=", purpose)
    .where("expires_at", ">", new Date())
    .returning("challenge")
    .executeTakeFirst();
  if (!row) throw new ApiError(400, "challenge_expired", "This passkey request expired. Please try again.");
  return row.challenge;
}

async function passkeysOf(tx: Tx, userId: string) {
  return tx
    .selectFrom("auth_factors")
    .select(["id", "credential_id", "public_key", "sign_count", "transports"])
    .where("user_id", "=", userId)
    .where("type", "=", "webauthn")
    .where("verified_at", "is not", null)
    .execute();
}

async function authOptions(tx: Tx, deps: Deps, orgId: string, userId: string) {
  const creds = await passkeysOf(tx, userId);
  const options = await generateAuthenticationOptions({
    rpID: deps.cfg.rpId,
    userVerification: "required",
    allowCredentials: creds.map((c) => ({ id: c.credential_id!, transports: c.transports })),
  });
  const challenge_id = await storeChallenge(tx, orgId, userId, "webauthn_authenticate", options.challenge);
  return { challenge_id, options, hasPasskeys: creds.length > 0 };
}

/** Verifies an assertion against the user's registered passkeys; returns the factor ID used. */
async function verifyAssertion(tx: Tx, deps: Deps, userId: string, challengeId: string, response: AuthenticationResponseJSON) {
  const expectedChallenge = await takeChallenge(tx, challengeId, userId, "webauthn_authenticate");
  const cred = (await passkeysOf(tx, userId)).find((c) => c.credential_id === response.id);
  if (!cred || !cred.public_key) return null;
  const result = await verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: deps.cfg.publicUrl,
    expectedRPID: deps.cfg.rpId,
    requireUserVerification: true,
    credential: { id: cred.credential_id!, publicKey: new Uint8Array(cred.public_key), counter: Number(cred.sign_count), transports: cred.transports },
  }).catch(() => null);
  if (!result?.verified) return null;
  await tx
    .updateTable("auth_factors")
    .set({ sign_count: result.authenticationInfo.newCounter, last_used_at: new Date() })
    .where("id", "=", cred.id)
    .execute();
  return cred.id;
}

type Lookup = { user_id: string; org_id: string; status: string };

export function registerPasskeyRoutes(app: App) {
  // ---- Registration (signed in, or during mandatory enrollment) ----------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/factors/webauthn/options",
      tags: ["Me"],
      summary: "Start adding a passkey",
      security: bearer,
      responses: { 200: json(Ceremony), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowEnroll: true });
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const user = await tx.selectFrom("users").select(["email", "given_name", "family_name"]).where("id", "=", p.userId).executeTakeFirstOrThrow();
        const existing = await passkeysOf(tx, p.userId);
        const options = await generateRegistrationOptions({
          rpName: deps.cfg.rpName,
          rpID: deps.cfg.rpId,
          userName: user.email,
          userDisplayName: `${user.given_name} ${user.family_name}`.trim() || user.email,
          userID: new TextEncoder().encode(p.userId),
          attestationType: "none",
          excludeCredentials: existing.map((c) => ({ id: c.credential_id!, transports: c.transports })),
          authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
        });
        const challenge_id = await storeChallenge(tx, p.orgId, p.userId, "webauthn_register", options.challenge);
        return { challenge_id, options };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/factors/webauthn",
      tags: ["Me"],
      summary: "Finish adding a passkey",
      security: bearer,
      request: body(z.object({ challenge_id: Id, name: z.string().trim().min(1).max(64).default("Passkey"), response: CredentialResponse })),
      responses: { 201: json(Factor, "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowEnroll: true });
      const deps = c.get("deps");
      const input = c.req.valid("json");
      const meta = c.get("meta");
      const row = await deps.db.tenant(p.orgId, async (tx) => {
        const expectedChallenge = await takeChallenge(tx, input.challenge_id, p.userId, "webauthn_register");
        const result = await verifyRegistrationResponse({
          response: input.response as unknown as RegistrationResponseJSON,
          expectedChallenge,
          expectedOrigin: deps.cfg.publicUrl,
          expectedRPID: deps.cfg.rpId,
          requireUserVerification: true,
        }).catch((err: Error) => {
          throw new ApiError(400, "passkey_invalid", `The passkey couldn't be verified: ${err.message}`);
        });
        if (!result.verified) throw new ApiError(400, "passkey_invalid", "The passkey couldn't be verified");
        const { credential } = result.registrationInfo;
        const dupe = await tx.selectFrom("auth_factors").select("id").where("credential_id", "=", credential.id).executeTakeFirst();
        if (dupe) throw conflict("passkey_exists", "This passkey is already registered");
        const now = new Date();
        const id = newId();
        const inserted = await tx
          .insertInto("auth_factors")
          .values({
            id,
            org_id: p.orgId,
            user_id: p.userId,
            type: "webauthn",
            name: input.name,
            secret_sealed: null,
            public_key: Buffer.from(credential.publicKey),
            credential_id: credential.id,
            sign_count: credential.counter,
            transports: credential.transports ?? [],
            verified_at: now,
            last_used_at: now,
            last_totp_step: null,
          })
          .returningAll()
          .executeTakeFirstOrThrow();
        await markFreshMfa(tx, p, "webauthn");
        await audit(tx, p.orgId, { principal: p, meta }, {
          type: "user.mfa_enrolled",
          target: { type: "user", id: p.userId },
          details: { factor: "webauthn", factor_id: id, backed_up: result.registrationInfo.credentialBackedUp },
        });
        await notifyUsers(tx, p.orgId, [p.userId], {
          category: "security.account",
          title: "Passkey added",
          body: `"${input.name}" can now be used to sign in. If this wasn't you, contact your administrator.`,
          link: "/settings/security",
        });
        return inserted;
      });
      return c.json(
        { id: row.id, type: row.type, name: row.name, verified: true, last_used_at: isoOrNull(row.last_used_at), created_at: iso(row.created_at) },
        201,
      );
    },
  );

  // ---- Passkey as the second factor (or step-up) --------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/mfa/webauthn/options",
      tags: ["Auth"],
      summary: "Start verifying with a passkey (second factor or step-up)",
      security: bearer,
      responses: { 200: json(Ceremony), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true });
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, (tx) => authOptions(tx, deps, p.orgId, p.userId));
      if (!out.hasPasskeys) throw notFound("Passkey");
      return c.json({ challenge_id: out.challenge_id, options: out.options }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/mfa/webauthn",
      tags: ["Auth"],
      summary: "Finish verifying with a passkey",
      security: bearer,
      request: body(z.object({ challenge_id: Id, response: CredentialResponse })),
      responses: { 200: json(z.object({ session: z.object({ id: Id, state: z.literal("active"), expires_at: z.string() }) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true });
      const deps = c.get("deps");
      const input = c.req.valid("json");
      const meta = c.get("meta");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const factorId = await verifyAssertion(tx, deps, p.userId, input.challenge_id, input.response as unknown as AuthenticationResponseJSON);
        if (!factorId) {
          await audit(tx, p.orgId, { principal: p, meta }, { type: "auth.mfa", outcome: "failure", details: { factor: "webauthn" } });
          return null;
        }
        return completeMfa(tx, p, meta, "webauthn");
      });
      if (!out) throw new ApiError(401, "passkey_invalid", "That passkey couldn't be verified. Try again or use another method.");
      return c.json({ session: { id: out.id, state: "active" as const, expires_at: iso(out.expires_at) } }, 200);
    },
  );

  // ---- Passwordless sign-in (email first) ---------------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/passkey/options",
      tags: ["Auth"],
      summary: "Start a passwordless sign-in with a passkey",
      description: "Always returns a ceremony, even for unknown emails, so the response doesn't reveal who has an account.",
      request: body(z.object({ email: z.email() })),
      responses: { 200: json(Ceremony), ...problemResponses },
    }),
    async (c) => {
      const { email } = c.req.valid("json");
      const deps = c.get("deps");
      if (!passkeyLimiter.take(`${email.toLowerCase()}|${c.get("meta").ip}`)) throw new ApiError(429, "rate_limited", "Too many attempts");
      const user = await findActiveUser(deps, email);
      await refuseIfFederationRequired(deps, email, user ?? undefined);
      if (user) {
        const out = await deps.db.tenant(user.org_id, (tx) => authOptions(tx, deps, user.org_id, user.user_id));
        if (out.hasPasskeys) return c.json({ challenge_id: out.challenge_id, options: out.options }, 200);
      }
      // Decoy with the same shape: no credentials, a challenge nobody stored.
      const options = await generateAuthenticationOptions({ rpID: deps.cfg.rpId, userVerification: "required", allowCredentials: [] });
      return c.json({ challenge_id: randomUUID(), options }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/passkey",
      tags: ["Auth"],
      summary: "Finish a passwordless sign-in",
      request: body(z.object({ email: z.email(), challenge_id: Id, response: CredentialResponse, client: z.enum(["web", "mobile", "cli"]).default("web") })),
      responses: {
        200: json(
          z
            .object({
              token: z.string(),
              session: z.object({ id: Id, state: z.literal("active"), expires_at: z.string() }),
              mfa: z.object({ required: z.literal(false), enrollment_required: z.literal(false), factors: z.array(z.string()) }),
            })
            .openapi("PasskeySignIn"),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const meta = c.get("meta");
      const invalid = new ApiError(401, "passkey_invalid", "That passkey couldn't be verified. Try again or use your password.");
      const user = await findActiveUser(deps, input.email);
      await refuseIfFederationRequired(deps, input.email, user ?? undefined);
      if (!user) throw invalid;
      const out = await deps.db.tenant(user.org_id, async (tx) => {
        const actor = { type: "user" as const, id: user.user_id, display: input.email.toLowerCase() };
        const factorId = await verifyAssertion(tx, deps, user.user_id, input.challenge_id, input.response as unknown as AuthenticationResponseJSON).catch(
          () => null,
        );
        if (!factorId) {
          await audit(tx, user.org_id, { meta }, { type: "auth.login", outcome: "failure", actor, details: { method: "passkey", reason: "bad_assertion" } });
          return null;
        }
        const settings = await getSettings(tx, user.org_id);
        const s = await createSession(tx, deps, meta, {
          orgId: user.org_id,
          userId: user.user_id,
          state: "active",
          client: input.client,
          activeTtlMs: settings.session_ttl_hours * 3600_000,
          mfaMethod: "webauthn",
        });
        await tx.updateTable("users").set({ last_login_at: new Date() }).where("id", "=", user.user_id).execute();
        await alertIfBreakGlass(tx, user.org_id, user.user_id, meta, "a passkey");
        await audit(tx, user.org_id, { meta }, {
          type: "auth.login",
          actor,
          sessionId: s.session.id,
          details: { method: "passkey", client: input.client, mfa: "passkey" },
        });
        return s;
      });
      if (!out) throw invalid;
      return c.json(
        {
          token: out.token,
          session: { id: out.session.id, state: "active" as const, expires_at: iso(out.session.expires_at) },
          mfa: { required: false as const, enrollment_required: false as const, factors: [] },
        },
        200,
      );
    },
  );
}

async function findActiveUser(deps: Deps, email: string) {
  const row = await deps.db.unscoped(async (tx) => {
    const r = await sql<Lookup>`SELECT user_id, org_id, status FROM nexus_auth_find_user(${email})`.execute(tx);
    return r.rows[0];
  });
  return row?.status === "active" ? row : null;
}

/** Marks the session fully authenticated after a successful second factor. */
async function completeMfa(tx: Tx, p: Principal, meta: Parameters<typeof audit>[2]["meta"], factor: string) {
  const settings = await getSettings(tx, p.orgId);
  const now = new Date();
  const s = await tx
    .updateTable("sessions")
    .set({
      state: "active",
      mfa_at: now,
      mfa_method: "webauthn",
      ...(p.sessionState === "pending_mfa" ? { expires_at: new Date(Date.now() + settings.session_ttl_hours * 3600_000) } : {}),
    })
    .where("id", "=", p.sessionId)
    .returning(["id", "expires_at"])
    .executeTakeFirstOrThrow();
  if (p.sessionState === "pending_mfa") await tx.updateTable("users").set({ last_login_at: now }).where("id", "=", p.userId).execute();
  await audit(tx, p.orgId, { principal: p, meta }, { type: p.sessionState === "pending_mfa" ? "auth.mfa" : "auth.step_up", details: { factor } });
  return s;
}

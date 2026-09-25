import { createRoute, z } from "@hono/zod-openapi";
import { createPublicKey, randomBytes, verify } from "node:crypto";
import { sql } from "kysely";
import type { App, Deps, Principal } from "../context.js";
import { audit } from "../audit/record.js";
import { notifyRoles, notifyUsers } from "../notify/send.js";
import { getSettings } from "../org/settings.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { requireSession } from "./guard.js";
import { RateLimiter } from "./ratelimit.js";
import { createSession, markFreshMfa } from "./routes.js";
import { hashToken, numberChoices } from "./tokens.js";

/**
 * Push MFA with Nexus Mobile (SPEC AUTH-04, MOB-02).
 *
 * Pairing: the console shows a one-time code as a QR; the phone generates an
 * Ed25519 key pair (private key stays in the device keystore behind biometrics)
 * and registers the public key as a `push` factor.
 *
 * Sign-in: the console creates a challenge and shows a two-digit number. The
 * phone shows three choices; the user taps the matching one and the app signs
 * `nexus-push-v1\n{challengeId}\n{decision}\n{choice}`. Number matching plus a
 * signature from the paired key defeats MFA-fatigue "just tap approve" attacks
 * and stolen session tokens alike. "This wasn't me" revokes the waiting session
 * and alerts security.
 */

const PAIRING_TTL_MS = 10 * 60_000;
const CHALLENGE_TTL_MS = 2 * 60_000;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const pushLimiter = new RateLimiter(5, 10 * 60_000); // per user: blunts MFA-fatigue spamming

export const signedMessage = (challengeId: string, decision: "approve" | "deny", choice: number | null) =>
  `nexus-push-v1\n${challengeId}\n${decision}\n${choice ?? ""}`;

function verifyEd25519(publicKey: Buffer, message: string, signatureB64u: string) {
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]), format: "der", type: "spki" });
    return verify(null, Buffer.from(message), key, Buffer.from(signatureB64u, "base64url"));
  } catch {
    return false;
  }
}

const ChallengeContext = z
  .object({ ip: z.string(), user_agent: z.string(), client: z.string(), requested_at: z.string() })
  .openapi("PushChallengeContext");

const PendingChallenge = z
  .object({
    id: Id,
    choices: z.array(z.number().int()).openapi({ description: "Three numbers; exactly one matches what the console shows" }),
    context: ChallengeContext,
    created_at: z.string(),
    expires_at: z.string(),
  })
  .openapi("PendingPushChallenge");

type Pairing = { pairing_id: string; org_id: string; user_id: string; session_id: string | null };

async function sendPushes(deps: Deps, tx: Tx, orgId: string, userId: string, challengeId: string) {
  const regs = await tx.selectFrom("push_registrations").select(["id", "platform", "token"]).where("user_id", "=", userId).execute();
  return regs.map((r) => async () => {
    const res = await deps.push.send(
      { platform: r.platform, token: r.token },
      { title: "Sign-in request", category: "auth.mfa_challenge", id: challengeId, priority: "high" },
    );
    // The app was uninstalled or the token rotated: stop pushing to it.
    if (res.invalidToken) await deps.db.tenant(orgId, (t) => t.deleteFrom("push_registrations").where("id", "=", r.id).execute());
    return res;
  });
}

export function registerPushRoutes(app: App) {
  // ---- Pairing ------------------------------------------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/factors/push/pairing",
      tags: ["Me"],
      summary: "Start pairing Nexus Mobile as an authenticator",
      description: "Show `pairing_url` as a QR code. It is valid for 10 minutes and works once.",
      security: bearer,
      responses: {
        201: json(z.object({ code: z.string(), pairing_url: z.string(), expires_at: z.string() }).openapi("PushPairing"), "Created"),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requireSession(c, { allowEnroll: true });
      const deps = c.get("deps");
      const code = `nxp_${randomBytes(24).toString("base64url")}`;
      const expires = new Date(Date.now() + PAIRING_TTL_MS);
      await deps.db.tenant(p.orgId, async (tx) => {
        // One live pairing code per user.
        await tx.deleteFrom("device_pairings").where("user_id", "=", p.userId).where("used_at", "is", null).execute();
        await tx
          .insertInto("device_pairings")
          .values({ id: newId(), org_id: p.orgId, user_id: p.userId, session_id: p.sessionId, code_hash: hashToken(code), expires_at: expires })
          .execute();
      });
      const url = `nexus://pair?code=${encodeURIComponent(code)}&api=${encodeURIComponent(deps.cfg.apiPublicUrl)}`;
      return c.json({ code, pairing_url: url, expires_at: iso(expires) }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/devices/pair",
      tags: ["Nexus Mobile"],
      summary: "Pair a phone using the code from the console (public; the code is the credential)",
      description: "Registers the phone's Ed25519 public key as a push factor and returns a mobile session.",
      request: body(
        z.object({
          code: z.string().max(200),
          public_key: z.string().openapi({ description: "Raw 32-byte Ed25519 public key, base64url" }),
          device_name: z.string().trim().min(1).max(64),
          platform: z.enum(["ios", "android", "web"]),
          push_token: z.string().max(4096).optional(),
        }),
      ),
      responses: {
        200: json(
          z
            .object({
              token: z.string(),
              factor_id: Id,
              user: z.object({ id: Id, email: z.string(), display_name: z.string() }),
              organization: z.object({ id: Id, name: z.string() }),
            })
            .openapi("PairedDevice"),
        ),
        ...problemResponses,
      },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const deps = c.get("deps");
      const meta = c.get("meta");
      const publicKey = Buffer.from(input.public_key, "base64url");
      if (publicKey.length !== 32) throw badRequest("invalid_public_key", "Expected a 32-byte Ed25519 public key");

      const pairing = await deps.db.unscoped(async (tx) => {
        const r = await sql<Pairing>`SELECT * FROM nexus_pairing_lookup(${hashToken(input.code)})`.execute(tx);
        return r.rows[0];
      });
      if (!pairing) throw new ApiError(404, "pairing_invalid", "This pairing code is invalid or expired. Show a new QR code in the console.");

      const out = await deps.db.tenant(pairing.org_id, async (tx) => {
        const used = await tx
          .updateTable("device_pairings")
          .set({ used_at: new Date() })
          .where("id", "=", pairing.pairing_id)
          .where("used_at", "is", null)
          .executeTakeFirst();
        if (Number(used.numUpdatedRows) === 0) throw new ApiError(404, "pairing_invalid", "This pairing code was already used.");

        const factorId = newId();
        const now = new Date();
        await tx
          .insertInto("auth_factors")
          .values({
            id: factorId,
            org_id: pairing.org_id,
            user_id: pairing.user_id,
            type: "push",
            name: input.device_name,
            secret_sealed: null,
            public_key: publicKey,
            credential_id: null,
            last_totp_step: null,
            verified_at: now,
            last_used_at: now,
          })
          .execute();
        if (input.push_token) {
          await tx
            .insertInto("push_registrations")
            .values({ id: newId(), org_id: pairing.org_id, user_id: pairing.user_id, factor_id: factorId, platform: input.platform, token: input.push_token, last_seen_at: now })
            .onConflict((oc) => oc.columns(["platform", "token"]).doUpdateSet({ user_id: pairing.user_id, factor_id: factorId, last_seen_at: now }))
            .execute();
        }
        // Pairing proves possession of a signed-in console session, so the phone's session counts as MFA'd.
        const s = await createSession(tx, deps, meta, {
          orgId: pairing.org_id,
          userId: pairing.user_id,
          state: "active",
          client: "mobile",
          activeTtlMs: 30 * 24 * 3600_000, // mobile stays signed in; revocable from the console at any time
          mfa: true,
        });
        await tx.updateTable("sessions").set({ factor_id: factorId }).where("id", "=", s.session.id).execute();
        // If the console was waiting on mandatory MFA enrollment, pairing completes it.
        if (pairing.session_id) {
          const web = await tx.selectFrom("sessions").select(["id", "state"]).where("id", "=", pairing.session_id).where("revoked_at", "is", null).executeTakeFirst();
          if (web) await markFreshMfa(tx, { orgId: pairing.org_id, sessionId: web.id, sessionState: web.state });
        }
        const user = await tx.selectFrom("users").select(["id", "email", "given_name", "family_name"]).where("id", "=", pairing.user_id).executeTakeFirstOrThrow();
        const org = await tx.selectFrom("organizations").select(["id", "name"]).where("id", "=", pairing.org_id).executeTakeFirstOrThrow();
        const actor = { type: "user" as const, id: user.id, display: user.email };
        await audit(tx, pairing.org_id, { meta }, {
          type: "user.mfa_enrolled",
          actor,
          sessionId: s.session.id,
          target: { type: "user", id: user.id, display: user.email },
          details: { factor: "push", factor_id: factorId, device: input.device_name, platform: input.platform },
        });
        await notifyUsers(tx, pairing.org_id, [user.id], {
          category: "security.account",
          title: `Nexus Mobile paired on ${input.device_name}`,
          body: "You can now approve sign-ins from your phone. If this wasn't you, remove the device and contact your administrator.",
          link: "/settings/security",
        });
        return {
          token: s.token,
          factor_id: factorId,
          user: { id: user.id, email: user.email, display_name: `${user.given_name} ${user.family_name}`.trim() || user.email },
          organization: { id: org.id, name: org.name },
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/me/push-registrations",
      tags: ["Nexus Mobile"],
      summary: "Register or refresh this phone's push token",
      security: bearer,
      request: body(z.object({ platform: z.enum(["ios", "android", "web"]), token: z.string().min(1).max(4096) })),
      responses: { 204: { description: "Saved" }, ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { platform, token } = c.req.valid("json");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await tx.selectFrom("sessions").select("factor_id").where("id", "=", p.sessionId).executeTakeFirst();
        const now = new Date();
        await tx
          .insertInto("push_registrations")
          .values({ id: newId(), org_id: p.orgId, user_id: p.userId, factor_id: s?.factor_id ?? null, platform, token, last_seen_at: now })
          .onConflict((oc) => oc.columns(["platform", "token"]).doUpdateSet({ user_id: p.userId, factor_id: s?.factor_id ?? null, last_seen_at: now }))
          .execute();
      });
      return c.body(null, 204);
    },
  );

  // ---- Challenge (console side) --------------------------------------------------

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/mfa/push",
      tags: ["Auth"],
      summary: "Send a push approval to the user's paired phone(s)",
      description: "Show `number` prominently; the user taps it on their phone. Watch `/v1/me/stream` (event `challenge`) or poll the status endpoint.",
      security: bearer,
      responses: {
        201: json(z.object({ challenge_id: Id, number: z.number().int(), expires_at: z.string() }).openapi("PushChallenge"), "Created"),
        ...problemResponses,
        429: { description: "Too many push requests" },
      },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true });
      const deps = c.get("deps");
      const meta = c.get("meta");
      if (!pushLimiter.take(p.userId)) {
        throw new ApiError(429, "rate_limited", "Too many push requests. Wait a few minutes or use another method.");
      }
      const { number, choices } = numberChoices();
      const id = newId();
      const expires = new Date(Date.now() + CHALLENGE_TTL_MS);
      const sends = await deps.db.tenant(p.orgId, async (tx) => {
        const phones = await tx.selectFrom("auth_factors").select("id").where("user_id", "=", p.userId).where("type", "=", "push").where("verified_at", "is not", null).execute();
        if (!phones.length) throw notFound("Paired phone");
        // Only one live challenge per session.
        await tx.updateTable("mfa_challenges").set({ status: "expired", decided_at: new Date() }).where("session_id", "=", p.sessionId).where("status", "=", "pending").execute();
        await tx
          .insertInto("mfa_challenges")
          .values({
            id,
            org_id: p.orgId,
            user_id: p.userId,
            session_id: p.sessionId,
            number,
            choices,
            context: JSON.stringify({ ip: meta.ip, user_agent: meta.userAgent.slice(0, 256), client: p.client, requested_at: new Date().toISOString() }),
            expires_at: expires,
          })
          .execute();
        return sendPushes(deps, tx, p.orgId, p.userId, id);
      });
      // Deliver after commit so the phone can always fetch what it was told about.
      await Promise.allSettled(sends.map((s) => s()));
      return c.json({ challenge_id: id, number, expires_at: iso(expires) }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/auth/mfa/push/{id}",
      tags: ["Auth"],
      summary: "Status of a push challenge started by this session",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: {
        200: json(z.object({ status: z.enum(["pending", "approved", "denied", "expired"]), reason: z.string().nullable() }).openapi("PushChallengeStatus")),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requireSession(c, { allowPendingMfa: true });
      const { id } = c.req.valid("param");
      const ch = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx.selectFrom("mfa_challenges").select(["status", "expires_at", "decision_reason"]).where("id", "=", id).where("session_id", "=", p.sessionId).executeTakeFirst(),
      );
      if (!ch) throw notFound("Challenge");
      const status = ch.status === "pending" && ch.expires_at < new Date() ? "expired" : ch.status;
      return c.json({ status, reason: ch.decision_reason }, 200);
    },
  );

  // ---- Challenge (phone side) ----------------------------------------------------

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/mfa-challenges",
      tags: ["Nexus Mobile"],
      summary: "Pending sign-in approvals for me",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(PendingChallenge) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx
          .selectFrom("mfa_challenges")
          .select(["id", "choices", "context", "created_at", "expires_at"])
          .where("user_id", "=", p.userId)
          .where("status", "=", "pending")
          .where("expires_at", ">", new Date())
          .orderBy("created_at", "desc")
          .limit(5)
          .execute(),
      );
      return c.json(
        {
          data: rows.map((r) => ({
            id: r.id,
            choices: r.choices,
            context: r.context as z.infer<typeof ChallengeContext>,
            created_at: iso(r.created_at),
            expires_at: iso(r.expires_at),
          })),
        },
        200,
      );
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/mfa-challenges/{id}/respond",
      tags: ["Nexus Mobile"],
      summary: "Approve or deny a sign-in from the paired phone",
      description:
        "`signature` is an Ed25519 signature (base64url) by the paired key over `nexus-push-v1\\n{id}\\n{decision}\\n{choice}` (choice empty when denying). Approving with the wrong number denies the challenge.",
      security: bearer,
      request: {
        params: z.object({ id: Id }),
        ...body(
          z.object({
            decision: z.enum(["approve", "deny"]),
            choice: z.number().int().optional(),
            reason: z.enum(["not_me", "mistake"]).optional(),
            factor_id: Id,
            signature: z.string().max(200),
          }),
        ),
      },
      responses: {
        200: json(z.object({ status: z.enum(["approved", "denied"]), reason: z.string().nullable() }).openapi("PushChallengeResult")),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requireSession(c);
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const meta = c.get("meta");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const ch = await tx.selectFrom("mfa_challenges").selectAll().where("id", "=", id).where("user_id", "=", p.userId).forUpdate().executeTakeFirst();
        if (!ch) throw notFound("Challenge");
        if (ch.status !== "pending") throw conflict("challenge_decided", "This request was already answered");
        if (ch.expires_at < new Date()) throw conflict("challenge_expired", "This request expired. Start the sign-in again.");

        const factor = await tx
          .selectFrom("auth_factors")
          .select(["id", "public_key", "name"])
          .where("id", "=", input.factor_id)
          .where("user_id", "=", p.userId)
          .where("type", "=", "push")
          .executeTakeFirst();
        if (!factor?.public_key) throw notFound("Paired device");
        const message = signedMessage(id, input.decision, input.decision === "approve" ? (input.choice ?? null) : null);
        if (!verifyEd25519(factor.public_key, message, input.signature)) {
          throw new ApiError(401, "invalid_signature", "The approval couldn't be verified with this device's key");
        }

        const who = { principal: p, meta };
        let status: "approved" | "denied";
        let reason: string | null = null;
        if (input.decision === "approve" && input.choice === ch.number) {
          status = "approved";
          await decide(tx, id, factor.id, "approved", null);
          const web = await tx.selectFrom("sessions").select(["id", "state"]).where("id", "=", ch.session_id).where("revoked_at", "is", null).executeTakeFirst();
          if (web) {
            await completeSession(tx, p.orgId, web.id, web.state);
            if (web.state === "pending_mfa") await tx.updateTable("users").set({ last_login_at: new Date() }).where("id", "=", p.userId).execute();
          }
          await tx.updateTable("auth_factors").set({ last_used_at: new Date() }).where("id", "=", factor.id).execute();
          await audit(tx, p.orgId, who, {
            type: web?.state === "active" ? "auth.step_up" : "auth.mfa",
            sessionId: ch.session_id,
            details: { factor: "push", device: factor.name, challenge_id: id },
          });
        } else {
          status = "denied";
          reason = input.decision === "approve" ? "wrong_number" : (input.reason ?? "mistake");
          await decide(tx, id, factor.id, "denied", reason);
          await audit(tx, p.orgId, who, {
            type: "auth.mfa",
            outcome: "denied",
            sessionId: ch.session_id,
            details: { factor: "push", device: factor.name, challenge_id: id, reason, context: ch.context },
          });
          if (reason !== "mistake") await raiseAlarm(tx, p, ch.session_id, reason, ch.context as { ip?: string });
        }
        return { status, reason };
      });
      return c.json(out, 200);
    },
  );
}

async function decide(tx: Tx, id: string, factorId: string, status: "approved" | "denied", reason: string | null) {
  await tx
    .updateTable("mfa_challenges")
    .set({ status, decided_at: new Date(), factor_id: factorId, decision_reason: reason })
    .where("id", "=", id)
    .execute();
}

async function completeSession(tx: Tx, orgId: string, sessionId: string, state: "pending_mfa" | "enroll_mfa" | "active") {
  const settings = await getSettings(tx, orgId);
  await tx
    .updateTable("sessions")
    .set({
      state: "active",
      mfa_at: new Date(),
      ...(state !== "active" ? { expires_at: new Date(Date.now() + settings.session_ttl_hours * 3600_000) } : {}),
    })
    .where("id", "=", sessionId)
    .execute();
}

/**
 * "This wasn't me" (or a wrong number) means someone else has the password and
 * is trying to sign in right now: kill that session and tell security.
 */
async function raiseAlarm(tx: Tx, p: Principal, sessionId: string, reason: string, context: { ip?: string }) {
  await tx.updateTable("sessions").set({ revoked_at: new Date() }).where("id", "=", sessionId).where("revoked_at", "is", null).execute();
  const why = reason === "not_me" ? "reported a sign-in they didn't start" : "chose the wrong number on a sign-in request";
  await notifyRoles(tx, p.orgId, ["owner", "admin", "security_analyst"], {
    category: "security.alert",
    severity: "critical",
    title: `${p.email} ${why}`,
    body: `The sign-in attempt${context.ip ? ` from ${context.ip}` : ""} was blocked and its session revoked. Their password may be compromised; consider containing the account.`,
    entity: { type: "user", id: p.userId },
    link: `/users/${p.userId}`,
  });
  await notifyUsers(tx, p.orgId, [p.userId], {
    category: "security.account",
    severity: "warning",
    title: "We blocked a sign-in to your account",
    body: "Change your password soon. Your security team has been notified.",
    link: "/settings/security",
  });
}


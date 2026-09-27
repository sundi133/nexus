import { createRoute, z } from "@hono/zod-openapi";
import { generateAuthenticationOptions, type AuthenticationResponseJSON } from "@simplewebauthn/server";
import { importJWK, jwtVerify, type JWK } from "jose";
import { sql } from "kysely";
import { randomBytes } from "node:crypto";
import type { App, Deps } from "../context.js";
import { AGENT_LOCAL_URL } from "../access/device-trust.js";
import { audit } from "../audit/record.js";
import { alertIfBreakGlass } from "../directory/break-glass.js";
import { refuseIfFederationRequired } from "../federation/enforce.js";
import { getSettings } from "../org/settings.js";
import { ApiError, badRequest, conflict, notFound } from "../platform/errors.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { requireSession } from "./guard.js";
import { storeChallenge, verifyAssertion } from "./passkeys.js";
import { RateLimiter } from "./ratelimit.js";
import { createSession } from "./routes.js";

/**
 * Sign in with a managed device (docs/DEVICE-SIGN-IN.md), like JumpCloud Go: no email, no
 * password. The sign-in page asks the local Nexus agent to attest which enrolled device it's on;
 * Nexus offers that device's assigned user their passkey bound to it; Touch ID or Windows Hello
 * verifies the person. Phishing-resistant (both proofs are origin-bound), and the session starts
 * device-verified, so conditional access sees the device at once.
 *
 * Nothing is stored before the device is known: the sign-in page's nonce and the passkey step's
 * state travel as short-lived sealed tickets.
 */

const TICKET_MS = 2 * 60_000;
const BIND_WITHIN_MS = 15 * 60_000;
const ATTEST_AUD = "nexus-device-attest";
const limiter = new RateLimiter(30, 5 * 60_000, "device-sign-in");

type Start = { k: "start"; nonce: string; exp: number };
type Pending = { k: "pending"; org: string; user: string; device: string; challenge: string; exp: number };

const seal = (deps: Deps, v: Start | Pending) => deps.sealer.seal(Buffer.from(JSON.stringify(v)), "device_sign_in").toString("base64url");
function unseal<T extends Start | Pending>(deps: Deps, ticket: string, kind: T["k"]): T {
  try {
    const v = JSON.parse(deps.sealer.open(Buffer.from(ticket, "base64url"), "device_sign_in").toString()) as T;
    if (v.k === kind && v.exp > Date.now()) return v;
  } catch {
    /* fall through */
  }
  throw new ApiError(400, "ticket_expired", "This sign-in expired. Start again.");
}

const unavailable = (why: string, code = "device_sign_in_unavailable") => new ApiError(409, code, why);

export function registerDeviceSignInRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/device/start",
      tags: ["Auth"],
      summary: "Start signing in with this managed device",
      description: "Send `nonce` to the local agent at `agent_url` (`POST /v1/attest`), then call `/v1/auth/device/options` with its attestation.",
      responses: { 200: json(z.object({ ticket: z.string(), nonce: z.string(), agent_url: z.string() })), ...problemResponses },
    }),
    async (c) => {
      if (!(await limiter.take(c.get("meta").ip))) throw new ApiError(429, "rate_limited", "Too many attempts");
      const nonce = randomBytes(32).toString("base64url");
      return c.json({ ticket: seal(c.get("deps"), { k: "start", nonce, exp: Date.now() + TICKET_MS }), nonce, agent_url: AGENT_LOCAL_URL }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/device/options",
      tags: ["Auth"],
      summary: "Check the device's attestation and get the passkey request for its user",
      request: body(z.object({ ticket: z.string().max(2000), attestation: z.string().max(4096) })),
      responses: {
        200: json(z.object({ ticket: z.string(), options: z.record(z.string(), z.unknown()), user: z.object({ name: z.string(), email: z.string() }), device: z.object({ hostname: z.string() }) })),
        ...problemResponses,
      },
    }),
    async (c) => {
      const deps = c.get("deps");
      const input = c.req.valid("json");
      if (!(await limiter.take(c.get("meta").ip))) throw new ApiError(429, "rate_limited", "Too many attempts");
      const start = unseal<Start>(deps, input.ticket, "start");
      const bad = (why: string) => new ApiError(400, "invalid_attestation", `This device couldn't be verified: ${why}`);
      let kid = "";
      try {
        kid = (JSON.parse(Buffer.from(input.attestation.split(".")[0]!, "base64url").toString()) as { kid?: string }).kid ?? "";
      } catch {
        throw bad("malformed attestation");
      }
      if (!/^[0-9a-f-]{36}$/.test(kid)) throw bad("missing device ID");
      const dev = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; public_jwk: JWK }>`SELECT * FROM nexus_device_auth(${kid}::uuid)`.execute(tx)).rows[0]);
      if (!dev) throw bad("this device isn't enrolled");
      const { payload } = await jwtVerify(input.attestation, await importJWK(dev.public_jwk, "ES256"), {
        audience: ATTEST_AUD,
        typ: "nexus-device+jwt",
        algorithms: ["ES256"],
        maxTokenAge: 120,
        clockTolerance: 30,
        requiredClaims: ["nonce", "origin", "iat", "exp"],
      }).catch((e: Error) => {
        throw bad(e.message);
      });
      if (payload.nonce !== start.nonce) throw bad("the attestation is for a different sign-in");
      if (payload.origin !== deps.cfg.publicUrl) throw bad("it came from another site");

      const out = await deps.db.tenant(dev.org_id, async (tx) => {
        const d = await tx.selectFrom("devices").select(["id", "hostname", "status", "compliance", "primary_user_id"]).where("id", "=", kid).executeTakeFirst();
        if (!d || d.status !== "active") throw bad("this device isn't enrolled");
        if (!d.primary_user_id) throw unavailable(`${d.hostname} isn't assigned to anyone, so it can't sign someone in. Use your email instead.`, "device_unassigned");
        if (d.compliance === "non_compliant") throw unavailable(`${d.hostname} doesn't meet your organization's device policies. Fix what My devices shows, or sign in with your email.`, "device_non_compliant");
        const u = await tx.selectFrom("users").select(["id", "email", "given_name", "family_name", "status"]).where("id", "=", d.primary_user_id).executeTakeFirstOrThrow();
        if (u.status !== "active") throw unavailable("The person this device is assigned to can't sign in", "user_inactive");
        await refuseIfFederationRequired(deps, u.email, { user_id: u.id, org_id: dev.org_id });
        const creds = await tx
          .selectFrom("auth_factors")
          .select(["credential_id", "transports"])
          .where("user_id", "=", u.id)
          .where("type", "=", "webauthn")
          .where("verified_at", "is not", null)
          .where("bound_device_id", "=", d.id)
          .execute();
        if (!creds.length) throw unavailable(`Sign-in with ${d.hostname} isn't set up yet. Sign in with your email, then choose "Sign in with this device" under My security.`, "not_set_up");
        const options = await generateAuthenticationOptions({ rpID: deps.cfg.rpId, userVerification: "required", allowCredentials: creds.map((x) => ({ id: x.credential_id!, transports: x.transports as never })) });
        const challenge = await storeChallenge(tx, dev.org_id, u.id, "webauthn_authenticate", options.challenge);
        return {
          ticket: seal(deps, { k: "pending", org: dev.org_id, user: u.id, device: d.id, challenge, exp: Date.now() + TICKET_MS }),
          options: options as unknown as Record<string, unknown>,
          user: { name: `${u.given_name} ${u.family_name}`.trim() || u.email, email: u.email },
          device: { hostname: d.hostname },
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/auth/device",
      tags: ["Auth"],
      summary: "Finish signing in with this device",
      request: body(z.object({ ticket: z.string().max(2000), response: z.record(z.string(), z.unknown()), client: z.enum(["web"]).default("web") })),
      responses: {
        200: json(z.object({ token: z.string(), session: z.object({ id: Id, state: z.literal("active"), expires_at: z.string() }), mfa: z.object({ required: z.literal(false), enrollment_required: z.literal(false), factors: z.array(z.string()) }) })),
        ...problemResponses,
      },
    }),
    async (c) => {
      const deps = c.get("deps");
      const meta = c.get("meta");
      const input = c.req.valid("json");
      const t = unseal<Pending>(deps, input.ticket, "pending");
      const invalid = new ApiError(401, "passkey_invalid", "That couldn't be verified. Try again, or sign in with your email.");
      const out = await deps.db.tenant(t.org, async (tx) => {
        const u = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", t.user).executeTakeFirstOrThrow();
        const actor = { type: "user" as const, id: t.user, display: u.email };
        const factorId = await verifyAssertion(tx, deps, t.user, t.challenge, input.response as unknown as AuthenticationResponseJSON).catch(() => null);
        // The passkey must be the one bound to the attested device, and it must still be assigned to them.
        const bound = factorId ? await tx.selectFrom("auth_factors").select("bound_device_id").where("id", "=", factorId).executeTakeFirst() : undefined;
        const d = await tx.selectFrom("devices").select(["hostname", "status", "primary_user_id", "compliance"]).where("id", "=", t.device).executeTakeFirst();
        if (!factorId || bound?.bound_device_id !== t.device || !d || d.status !== "active" || d.primary_user_id !== t.user || u.status !== "active") {
          await audit(tx, t.org, { meta }, { type: "auth.login", outcome: "failure", actor, details: { method: "device", reason: factorId ? "device_mismatch" : "bad_assertion" } });
          return null;
        }
        const settings = await getSettings(tx, t.org);
        const s = await createSession(tx, deps, meta, { orgId: t.org, userId: t.user, state: "active", client: input.client, activeTtlMs: settings.session_ttl_hours * 3600_000, mfaMethod: "webauthn" });
        // The session starts on a verified device: conditional access doesn't need to ask again.
        await tx.updateTable("sessions").set({ device_id: t.device, device_verified_at: new Date() }).where("id", "=", s.session.id).execute();
        await tx.updateTable("users").set({ last_login_at: new Date() }).where("id", "=", t.user).execute();
        await alertIfBreakGlass(tx, t.org, t.user, meta, "device sign-in");
        await audit(tx, t.org, { meta }, {
          type: "auth.login",
          actor,
          sessionId: s.session.id,
          target: { type: "device", id: t.device, display: d.hostname },
          details: { method: "device", client: input.client, mfa: "passkey", device: d.hostname, compliance: d.compliance },
        });
        return s;
      });
      if (!out) throw invalid;
      return c.json({ token: out.token, session: { id: out.session.id, state: "active" as const, expires_at: iso(out.session.expires_at) }, mfa: { required: false as const, enrollment_required: false as const, factors: [] } }, 200);
    },
  );

  // ---- Setting it up (signed in, on the device) ------------------------------------

  const Bound = z.object({ factor_id: Id, name: z.string(), device: z.object({ id: Id, hostname: z.string() }) }).openapi("DeviceSignIn");

  app.openapi(
    createRoute({ method: "get", path: "/v1/me/device-sign-in", tags: ["Me"], summary: "Devices you can sign in with", security: bearer, responses: { 200: json(z.object({ data: z.array(Bound), this_device: z.object({ id: Id, hostname: z.string() }).nullable() })), ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const rows = await tx
          .selectFrom("auth_factors")
          .innerJoin("devices", "devices.id", "auth_factors.bound_device_id")
          .select(["auth_factors.id", "auth_factors.name", "devices.id as device_id", "devices.hostname"])
          .where("auth_factors.user_id", "=", p.userId)
          .execute();
        const s = await tx.selectFrom("sessions").leftJoin("devices", "devices.id", "sessions.device_id").select(["sessions.device_id", "devices.hostname", "sessions.device_verified_at"]).where("sessions.id", "=", p.sessionId).executeTakeFirst();
        return { data: rows.map((r) => ({ factor_id: r.id, name: r.name, device: { id: r.device_id, hostname: r.hostname } })), this_device: s?.device_id && s.hostname ? { id: s.device_id, hostname: s.hostname } : null };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/device-sign-in",
      tags: ["Me"],
      summary: "Let a passkey sign you in on this device",
      description: "The session must have verified the device (device trust) in the last 15 minutes, and the device must be assigned to you. Use a passkey made on this device (Touch ID, Windows Hello).",
      security: bearer,
      request: body(z.object({ factor_id: Id })),
      responses: { 200: json(Bound), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { factor_id } = c.req.valid("json");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const s = await tx.selectFrom("sessions").select(["device_id", "device_verified_at"]).where("id", "=", p.sessionId).executeTakeFirst();
        if (!s?.device_id || !s.device_verified_at || Date.now() - s.device_verified_at.getTime() > BIND_WITHIN_MS) throw conflict("device_not_verified", "Verify this device first (the Nexus agent must be running on it)");
        const d = await tx.selectFrom("devices").select(["id", "hostname", "primary_user_id", "status"]).where("id", "=", s.device_id).executeTakeFirstOrThrow();
        if (d.status !== "active" || d.primary_user_id !== p.userId) throw conflict("not_your_device", `${d.hostname} isn't assigned to you`);
        const f = await tx.selectFrom("auth_factors").select(["id", "name"]).where("id", "=", factor_id).where("user_id", "=", p.userId).where("type", "=", "webauthn").where("verified_at", "is not", null).executeTakeFirst();
        if (!f) throw notFound("Passkey");
        await tx.updateTable("auth_factors").set({ bound_device_id: d.id }).where("id", "=", f.id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "auth.device_sign_in_enabled", target: { type: "device", id: d.id, display: d.hostname }, details: { factor_id: f.id } });
        return { factor_id: f.id, name: f.name, device: { id: d.id, hostname: d.hostname } };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/me/device-sign-in/{factor_id}", tags: ["Me"], summary: "Stop a passkey signing you in with a device (it stays a passkey)", security: bearer, request: { params: z.object({ factor_id: Id }) }, responses: { 204: { description: "Removed" }, ...problemResponses } }),
    async (c) => {
      const p = requireSession(c);
      const { factor_id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.updateTable("auth_factors").set({ bound_device_id: null }).where("id", "=", factor_id).where("user_id", "=", p.userId).where("bound_device_id", "is not", null).returning("id").executeTakeFirst();
        if (!r) throw badRequest("not_bound", "That passkey isn't set up for device sign-in");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "auth.device_sign_in_disabled", details: { factor_id } });
      });
      return c.body(null, 204);
    },
  );
}

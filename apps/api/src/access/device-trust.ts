import { createRoute, z } from "@hono/zod-openapi";
import { importJWK, jwtVerify, type JWK } from "jose";
import { randomBytes } from "node:crypto";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requireSession } from "../auth/guard.js";
import { ApiError } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, json, problemResponses } from "../schemas.js";

/**
 * Device trust for browser sign-ins (SPEC CA-05).
 *
 * The console asks the local Nexus agent (127.0.0.1 only) to sign a one-time,
 * session-bound nonce with the device key. The agent answers only the Nexus
 * web origin (enforced by the browser-set Origin header) and includes that
 * origin in the signed statement, so a malicious site on the same machine
 * can't obtain an attestation for an attacker's session.
 */

export const AGENT_LOCAL_URL = "http://127.0.0.1:47823";
const CHALLENGE_TTL_MS = 2 * 60_000;
const AUD = "nexus-device-attest";

const TrustedDevice = z
  .object({ id: Id, hostname: z.string(), compliance: z.enum(["compliant", "non_compliant", "unknown"]), verified_at: z.string() })
  .openapi("TrustedDevice");

export function registerDeviceTrustRoutes(app: App) {
  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/device-trust/challenge",
      tags: ["Me"],
      summary: "Start proving which managed device this browser session is on",
      description: "Send `nonce` to the local agent at `agent_url` (`POST /v1/attest`), then submit its attestation.",
      security: bearer,
      responses: { 201: json(z.object({ challenge_id: Id, nonce: z.string(), agent_url: z.string() }).openapi("DeviceTrustChallenge"), "Created"), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const id = newId();
      const nonce = randomBytes(32).toString("base64url");
      await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx.insertInto("device_trust_challenges").values({ id, org_id: p.orgId, session_id: p.sessionId, nonce, expires_at: new Date(Date.now() + CHALLENGE_TTL_MS) }).execute(),
      );
      return c.json({ challenge_id: id, nonce, agent_url: AGENT_LOCAL_URL }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/me/device-trust",
      tags: ["Me"],
      summary: "Bind this session to the device that signed the challenge",
      security: bearer,
      request: body(z.object({ challenge_id: Id, attestation: z.string().max(4096) })),
      responses: { 200: json(TrustedDevice), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const { challenge_id, attestation } = c.req.valid("json");
      const deps = c.get("deps");
      const invalid = (why: string) => new ApiError(400, "invalid_attestation", `The device couldn't be verified: ${why}`);
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        // Single use, this session only, not expired.
        const ch = await tx
          .updateTable("device_trust_challenges")
          .set({ used_at: new Date() })
          .where("id", "=", challenge_id)
          .where("session_id", "=", p.sessionId)
          .where("used_at", "is", null)
          .where("expires_at", ">", new Date())
          .returning("nonce")
          .executeTakeFirst();
        if (!ch) throw invalid("the challenge is unknown, expired or already used");

        let kid = "";
        try {
          kid = (JSON.parse(Buffer.from(attestation.split(".")[0]!, "base64url").toString()) as { kid?: string }).kid ?? "";
        } catch {
          throw invalid("malformed attestation");
        }
        if (!/^[0-9a-f-]{36}$/.test(kid)) throw invalid("missing device ID");
        // RLS scopes this to the session's organization: another org's device can't vouch here.
        const device = await tx.selectFrom("devices").select(["id", "hostname", "public_jwk", "status", "compliance", "primary_user_id"]).where("id", "=", kid).executeTakeFirst();
        if (!device || device.status !== "active") throw invalid("this device isn't enrolled in your organization");
        // Shared (unassigned) devices can vouch for anyone; a personal device only for its user.
        if (device.primary_user_id && device.primary_user_id !== p.userId) throw invalid(`${device.hostname} is assigned to someone else`);

        const { payload } = await jwtVerify(attestation, await importJWK(device.public_jwk as JWK, "ES256"), {
          audience: AUD,
          typ: "nexus-device+jwt",
          algorithms: ["ES256"],
          maxTokenAge: 120,
          clockTolerance: 30,
          requiredClaims: ["nonce", "origin", "iat", "exp"],
        }).catch((e: Error) => {
          throw invalid(e.message);
        });
        if (payload.nonce !== ch.nonce) throw invalid("the attestation is for a different challenge");
        if (payload.origin !== deps.cfg.publicUrl) throw invalid(`the request came from ${String(payload.origin)}, not from Nexus`);

        const now = new Date();
        await tx.updateTable("sessions").set({ device_id: device.id, device_verified_at: now }).where("id", "=", p.sessionId).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: "device.trust_verified",
          target: { type: "device", id: device.id, display: device.hostname },
          details: { session_id: p.sessionId, compliance: device.compliance },
        });
        return { id: device.id, hostname: device.hostname, compliance: device.compliance, verified_at: now.toISOString() };
      });
      return c.json(out, 200);
    },
  );
}

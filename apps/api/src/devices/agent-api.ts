import { z } from "@hono/zod-openapi";
import type { Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { calculateJwkThumbprint, EmbeddedJWK, importJWK, jwtVerify, type JWK } from "jose";
import { sql } from "kysely";
import { createHash } from "node:crypto";
import type { App, Env } from "../context.js";
import { audit } from "../audit/record.js";
import { hashToken } from "../auth/tokens.js";
import { ApiError, badRequest, conflict } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { CHECKIN_INTERVAL_S, evaluateDevice, getPolicies, INVENTORY_INTERVAL_S } from "./service.js";
import { PostureFacts } from "./posture.js";

/**
 * Agent API (ARCHITECTURE §8, ADR-015). Every request carries
 * `Authorization: NexusDevice <jwt>`, an ES256 JWT signed by the device's own
 * key (DPoP-style proof of possession):
 *   header  { alg: ES256, typ: "nexus-device+jwt", kid: <device id> }   (enroll: `jwk` instead of `kid`)
 *   claims  { aud: "nexus-agent", htm, htu (path), bsh (base64url SHA-256 of the body), jti, iat, exp }
 * Lifetime ≤ 5 minutes, jti single-use, bound to method, path and body.
 */

const AUD = "nexus-agent";
const TYP = "nexus-device+jwt";
const MAX_AGE_S = 300;

const P256Jwk = z.object({
  kty: z.literal("EC"),
  crv: z.literal("P-256"),
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  y: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});

const DeviceInfo = z.object({
  hostname: z.string().trim().min(1).max(255),
  platform: z.enum(["macos", "windows", "linux"]),
  os_name: z.string().max(100).default(""),
  os_version: z.string().max(50).default(""),
  os_build: z.string().max(50).default(""),
  arch: z.string().max(20).default(""),
  model: z.string().max(200).default(""),
  serial: z.string().max(100).default(""),
  agent_version: z.string().max(40).default(""),
});

const EnrollBody = z.object({ token: z.string().max(200), device: DeviceInfo });

const Inventory = z
  .object({
    cpu: z.string().max(200).optional(),
    memory_bytes: z.number().int().nonnegative().optional(),
    disks: z.array(z.object({ mount: z.string().max(200), size_bytes: z.number().int().nonnegative(), encrypted: z.boolean().nullable().optional() })).max(50).optional(),
    local_users: z.array(z.object({ name: z.string().max(100), admin: z.boolean() })).max(200).optional(),
    console_user: z.string().max(100).nullable().optional(),
    uptime_seconds: z.number().int().nonnegative().optional(),
  })
  .passthrough();

// No defaults here: a field the agent doesn't send must leave the stored value alone.
const DeviceUpdate = z.object({
  hostname: z.string().trim().min(1).max(255),
  os_name: z.string().max(100),
  os_version: z.string().max(50),
  os_build: z.string().max(50),
  arch: z.string().max(20),
  model: z.string().max(200),
  serial: z.string().max(100),
  agent_version: z.string().max(40),
}).partial();

const CheckinBody = z.object({
  device: DeviceUpdate,
  posture: PostureFacts,
  inventory: Inventory.optional(),
});

const bsh = (body: string) => createHash("sha256").update(body).digest("base64url");

function deviceError(status: 401 | 403, code: string, message: string) {
  return new ApiError(status, code, message);
}

/** Verifies the proof JWT against a key; returns claims. Throws 401 on any mismatch. */
async function verifyProof(c: Context<Env>, token: string, key: Parameters<typeof jwtVerify>[1], body: string) {
  const { payload } = await jwtVerify(token, key as never, {
    audience: AUD,
    typ: TYP,
    algorithms: ["ES256"],
    maxTokenAge: MAX_AGE_S,
    clockTolerance: 60,
    requiredClaims: ["jti", "iat", "exp", "htm", "htu", "bsh"],
  }).catch((err: Error) => {
    throw deviceError(401, "invalid_device_proof", `Device signature rejected: ${err.message}`);
  });
  if (payload.htm !== c.req.method || payload.htu !== c.req.path) throw deviceError(401, "invalid_device_proof", "Signature is for a different request");
  if (payload.bsh !== bsh(body)) throw deviceError(401, "invalid_device_proof", "Body doesn't match the signature");
  if ((payload.exp ?? 0) - (payload.iat ?? 0) > MAX_AGE_S) throw deviceError(401, "invalid_device_proof", "Signature lifetime too long");
  return payload;
}

const authHeader = (c: Context<Env>) => {
  const h = c.req.header("authorization");
  if (!h?.startsWith("NexusDevice ")) throw deviceError(401, "device_auth_required", "Missing device signature");
  return h.slice("NexusDevice ".length).trim();
};

const parse = <T extends z.ZodTypeAny>(schema: T, raw: string): z.infer<T> => {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw badRequest("invalid_json", "Body must be JSON");
  }
  const r = schema.safeParse(json);
  if (!r.success) throw badRequest("invalid_request", "Some fields are invalid", { errors: r.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
  return r.data;
};

export function registerAgentRoutes(app: App) {
  // Agents are unauthenticated until the proof is checked, so cap the body before reading it.
  app.use(
    "/v1/agent/*",
    bodyLimit({ maxSize: 256 * 1024, onError: () => { throw new ApiError(413, "payload_too_large", "Request body is too large"); } }),
  );

  app.openAPIRegistry.registerPath({
    method: "post",
    path: "/v1/agent/enroll",
    tags: ["Agent"],
    summary: "Enroll a device (called by the Nexus agent)",
    description: "Body `{token, device}`. The `NexusDevice` proof JWT carries the device's new public key in its `jwk` header.",
    responses: { 201: { description: "Enrolled: `{device_id, organization, checkin_interval_seconds}`" } },
  });
  app.post("/v1/agent/enroll", async (c) => {
    const deps = c.get("deps");
    const meta = c.get("meta");
    const raw = await c.req.text();
    const proof = authHeader(c);
    // Proof of possession: the request is signed by the key being registered.
    await verifyProof(c, proof, EmbeddedJWK, raw);
    const header = JSON.parse(Buffer.from(proof.split(".")[0]!, "base64url").toString()) as { jwk?: unknown };
    const jwk = P256Jwk.safeParse(header.jwk);
    if (!jwk.success) throw deviceError(401, "invalid_device_proof", "Device key must be an EC P-256 public key");
    await importJWK(jwk.data, "ES256"); // rejects points not on the curve
    const thumbprint = await calculateJwkThumbprint(jwk.data as JWK, "sha256");
    const input = parse(EnrollBody, raw);

    const found = await deps.db.unscoped(async (tx) => (await sql<{ token_id: string; org_id: string }>`SELECT * FROM nexus_enrollment_lookup(${hashToken(input.token)})`.execute(tx)).rows[0]);
    if (!found) throw deviceError(401, "invalid_enrollment_token", "This enrollment token is invalid, expired or used up");

    const out = await deps.db.tenant(found.org_id, async (tx) => {
      // Consume one use atomically.
      const tok = await tx
        .updateTable("device_enrollment_tokens")
        .set((eb) => ({ uses: eb("uses", "+", 1) }))
        .where("id", "=", found.token_id)
        .where((eb) => eb.or([eb("max_uses", "is", null), eb("uses", "<", eb.ref("max_uses"))]))
        .returning(["id", "name", "assign_user_id"])
        .executeTakeFirst();
      if (!tok) throw deviceError(401, "invalid_enrollment_token", "This enrollment token is used up");
      const dupe = await sql<{ n: number }>`SELECT count(*)::int AS n FROM devices WHERE key_thumbprint = ${thumbprint}`.execute(tx);
      if (dupe.rows[0]!.n > 0) throw conflict("already_enrolled", "This device key is already enrolled");
      const id = newId();
      const now = new Date();
      await tx
        .insertInto("devices")
        .values({
          id,
          org_id: found.org_id,
          ...input.device,
          public_jwk: JSON.stringify(jwk.data),
          key_thumbprint: thumbprint,
          primary_user_id: tok.assign_user_id,
          enrollment_token_id: tok.id,
          inventory: JSON.stringify({}),
          posture: JSON.stringify({}),
          last_seen_at: now,
          last_ip: meta.ip,
          updated_at: now,
        })
        .execute();
      await audit(tx, found.org_id, { meta }, {
        type: "device.enrolled",
        actor: { type: "system", id: null, display: `Nexus agent ${input.device.agent_version}`.trim() },
        target: { type: "device", id, display: input.device.hostname },
        details: { platform: input.device.platform, os_version: input.device.os_version, serial: input.device.serial, token: tok.name, assigned_user_id: tok.assign_user_id },
      });
      const org = await tx.selectFrom("organizations").select("name").where("id", "=", found.org_id).executeTakeFirstOrThrow();
      return { device_id: id, organization: org.name, checkin_interval_seconds: CHECKIN_INTERVAL_S };
    });
    return c.json(out, 201);
  });

  app.openAPIRegistry.registerPath({
    method: "post",
    path: "/v1/agent/checkin",
    tags: ["Agent"],
    summary: "Report posture and inventory (called by the Nexus agent every minute)",
    description: "Body `{device, posture, inventory?}`, signed with the device key (`kid` = device ID). Returns the next check-in intervals.",
    responses: { 200: { description: "`{checkin_interval_seconds, inventory_interval_seconds, compliance}`" } },
  });
  app.post("/v1/agent/checkin", async (c) => {
    const deps = c.get("deps");
    const meta = c.get("meta");
    const raw = await c.req.text();
    const proof = authHeader(c);
    const kid = (JSON.parse(Buffer.from(proof.split(".")[0] ?? "", "base64url").toString() || "{}") as { kid?: string }).kid ?? "";
    if (!/^[0-9a-f-]{36}$/.test(kid)) throw deviceError(401, "invalid_device_proof", "Missing device ID");
    const dev = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; public_jwk: JWK }>`SELECT * FROM nexus_device_auth(${kid}::uuid)`.execute(tx)).rows[0]);
    // Removed devices must stop: the agent treats this code as "unenrolled".
    if (!dev) throw deviceError(401, "device_not_enrolled", "This device is not enrolled (it may have been removed)");
    const payload = await verifyProof(c, proof, await importJWK(dev.public_jwk, "ES256"), raw);
    const input = parse(CheckinBody, raw);

    const out = await deps.db.tenant(dev.org_id, async (tx) => {
      // Replay protection: a proof can be used once.
      await tx.deleteFrom("agent_nonces").where("device_id", "=", kid).where("expires_at", "<", new Date()).execute();
      const fresh = await tx
        .insertInto("agent_nonces")
        .values({ jti: String(payload.jti), org_id: dev.org_id, device_id: kid, expires_at: new Date((payload.exp ?? 0) * 1000) })
        .onConflict((oc) => oc.doNothing())
        .returning("jti")
        .executeTakeFirst();
      if (!fresh) throw deviceError(401, "replayed_device_proof", "This signed request was already used");

      const d = await tx
        .updateTable("devices")
        .set({
          ...Object.fromEntries(Object.entries(input.device).filter(([, v]) => v !== undefined)),
          posture: JSON.stringify(input.posture),
          ...(input.inventory ? { inventory: JSON.stringify(input.inventory) } : {}),
          last_seen_at: new Date(),
          last_ip: meta.ip,
          updated_at: new Date(),
        })
        .where("id", "=", kid)
        .returning(["id", "org_id", "hostname", "platform", "os_version", "posture", "compliance", "primary_user_id"])
        .executeTakeFirstOrThrow();
      const { compliance } = await evaluateDevice(tx, d, await getPolicies(tx), { meta });
      return { checkin_interval_seconds: CHECKIN_INTERVAL_S, inventory_interval_seconds: INVENTORY_INTERVAL_S, compliance };
    });
    return c.json(out, 200);
  });
}

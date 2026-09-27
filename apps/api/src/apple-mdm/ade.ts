import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { randomBytes, webcrypto } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import { sql } from "kysely";
import plist from "plist";
import type { App, Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest } from "../platform/errors.js";
import type { JobRunner } from "../platform/jobs.js";
import { bearer, body, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { DepClient, DepError, openServerToken, type DepDevice, type DepToken } from "./dep.js";
import { openSignedContent, SignatureError } from "./pki.js";
import { issueProfile } from "./protocol.js";

/**
 * Zero-touch enrollment (Apple Business Manager / Automated Device Enrollment). Nexus makes the
 * key ABM encrypts the server token to; with the token it signs in to Apple's device enrollment
 * service, syncs the Macs assigned to it every hour, and assigns them its enrollment profile. In
 * Setup Assistant each Mac posts its signed machine info to this org's enrollment URL and gets
 * its MDM enrollment profile, so it's managed from first boot.
 */

const keyAad = (org: string) => `apple_ade_key:${org}`;
const tokenAad = (org: string) => `apple_ade_token:${org}`;
const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;
const pem = (label: string, der: ArrayBuffer) => `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;
x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const SETUP_ITEMS = ["Location", "Restore", "AppleID", "TOS", "Siri", "Diagnostics", "Privacy", "ScreenTime", "Appearance", "FileVault", "iCloudDiagnostics", "iCloudStorage", "TouchId", "Payment", "Accessibility", "TrueToneDisplay", "UnlockWithWatch", "Wallpaper"] as const;
const ProfileIn = z.object({
  profile_name: z.string().trim().min(1).max(100).default("Votal Nexus"),
  department: z.string().trim().max(100).default(""),
  support_phone_number: z.string().trim().max(40).default(""),
  support_email_address: z.string().trim().max(200).default(""),
  is_mdm_removable: z.boolean().default(false).openapi({ description: "Let people remove device management in System Settings" }),
  skip_setup_items: z.array(z.enum(SETUP_ITEMS)).default(["Siri", "Diagnostics", "ScreenTime", "AppleID", "Payment"]),
  auto_assign: z.boolean().default(true).openapi({ description: "Assign this profile to every Mac Apple Business Manager assigns to Nexus" }),
});
type ProfileIn = z.infer<typeof ProfileIn>;

async function client(tx: Tx, deps: Deps, orgId: string) {
  const s = await tx.selectFrom("apple_ade_settings").selectAll().where("org_id", "=", orgId).executeTakeFirst();
  if (!s?.token) throw badRequest("ade_not_connected", "Connect Apple Business Manager first (upload the server token)");
  const token = JSON.parse(deps.sealer.open(s.token, tokenAad(orgId)).toString()) as DepToken;
  return { s, dep: new DepClient(deps.cfg.appleDepBase, token) };
}

const enrollUrl = (deps: Deps, secret: string) => `${deps.cfg.apiPublicUrl}/mdm/apple/ade/${secret}/enroll`;

/** Defines the enrollment profile at Apple and (optionally) assigns it to every Mac. */
async function defineProfile(tx: Tx, deps: Deps, orgId: string, p: ProfileIn) {
  const { s, dep } = await client(tx, deps, orgId);
  const serials = (await tx.selectFrom("apple_ade_devices").select("serial").where("deleted", "=", false).execute()).map((d) => d.serial);
  const r = await dep.defineProfile({
    profile_name: p.profile_name,
    url: enrollUrl(deps, s.enroll_secret),
    is_mdm_removable: p.is_mdm_removable,
    is_mandatory: true,
    is_supervised: true,
    await_device_configured: false,
    department: p.department,
    support_phone_number: p.support_phone_number,
    support_email_address: p.support_email_address,
    skip_setup_items: p.skip_setup_items,
    ...(p.auto_assign && serials.length ? { devices: serials.slice(0, 1000) } : {}),
  });
  await tx.updateTable("apple_ade_settings").set({ profile_uuid: r.profile_uuid, profile: JSON.stringify(p), auto_assign: p.auto_assign, updated_at: new Date() }).where("org_id", "=", orgId).execute();
  if (p.auto_assign && serials.length > 1000) await assignIn(dep, r.profile_uuid, serials.slice(1000));
  if (p.auto_assign) await tx.updateTable("apple_ade_devices").set({ profile_uuid: r.profile_uuid, profile_status: "assigned", assigned_at: new Date() }).where("deleted", "=", false).execute();
  return r.profile_uuid;
}

async function assignIn(dep: DepClient, uuid: string, serials: string[]) {
  for (let i = 0; i < serials.length; i += 1000) await dep.assign(uuid, serials.slice(i, i + 1000));
}

/** One sync: devices added, changed or removed in ABM since the cursor; new ones get the profile. */
export async function syncAde(tx: Tx, deps: Deps, orgId: string, meta: RequestMeta) {
  const { s, dep } = await client(tx, deps, orgId);
  try {
    const { devices, cursor } = s.cursor ? await dep.changes(s.cursor) : await dep.allDevices();
    const fresh: string[] = [];
    for (const d of devices as DepDevice[]) {
      if (!d.serial_number) continue;
      if (d.op_type === "deleted") {
        await tx.updateTable("apple_ade_devices").set({ deleted: true, updated_at: new Date() }).where("serial", "=", d.serial_number).execute();
        continue;
      }
      const fields = { model: d.model ?? "", description: d.description ?? "", color: d.color ?? "", os: d.os ?? "", profile_status: d.profile_status ?? "", profile_uuid: d.profile_uuid ?? "", deleted: false, updated_at: new Date() };
      await tx.insertInto("apple_ade_devices").values({ org_id: orgId, serial: d.serial_number, ...fields }).onConflict((oc) => oc.columns(["org_id", "serial"]).doUpdateSet(fields)).execute();
      if (s.profile_uuid && d.profile_uuid !== s.profile_uuid) fresh.push(d.serial_number);
    }
    let assigned = 0;
    if (s.auto_assign && s.profile_uuid && fresh.length) {
      await assignIn(dep, s.profile_uuid, fresh);
      await tx.updateTable("apple_ade_devices").set({ profile_uuid: s.profile_uuid, profile_status: "assigned", assigned_at: new Date() }).where("serial", "in", fresh).execute();
      assigned = fresh.length;
    }
    await tx.updateTable("apple_ade_settings").set({ cursor, last_sync_at: new Date(), last_error: "" }).where("org_id", "=", orgId).execute();
    if (devices.length) await audit(tx, orgId, { meta }, { type: "apple_mdm.ade_synced", actor: { type: "system", id: null, display: "Apple Business Manager sync" }, target: { type: "organization", id: orgId }, details: { changes: devices.length, assigned } });
    return { changes: devices.length, assigned };
  } catch (e) {
    const msg = e instanceof DepError ? e.message : `Sync failed: ${(e as Error).message}`;
    await tx.updateTable("apple_ade_settings").set({ last_error: msg.slice(0, 500), last_sync_at: new Date() }).where("org_id", "=", orgId).execute();
    throw new ApiError(502, "ade_sync_failed", msg);
  }
}

export function scheduleAdeSyncs(jobs: JobRunner, deps: Deps) {
  jobs.every("apple.ade_sync", 60 * 60_000, async () => {
    const orgs = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_apple_ade_orgs()`.execute(tx)).rows);
    for (const o of orgs) {
      await deps.db.tenant(o.org_id, (tx) => syncAde(tx, deps, o.org_id, { ip: "", userAgent: "nexus-scheduler", requestId: "" })).catch(() => undefined); // recorded as last_error
    }
  });
}

const Status = z
  .object({
    key_ready: z.boolean(),
    connected: z.boolean(),
    server_name: z.string(),
    abm_org_name: z.string(),
    token_expires_at: z.string().nullable(),
    devices: z.number().int(),
    last_sync_at: z.string().nullable(),
    last_error: z.string(),
    profile: ProfileIn.partial().nullable(),
    enroll_url: z.string().nullable(),
  })
  .openapi("AppleAdeStatus");

async function status(tx: Tx, deps: Deps, orgId: string): Promise<z.infer<typeof Status>> {
  const s = await tx.selectFrom("apple_ade_settings").selectAll().where("org_id", "=", orgId).executeTakeFirst();
  const n = (await tx.selectFrom("apple_ade_devices").select((eb) => eb.fn.countAll<number>().as("n")).where("deleted", "=", false).executeTakeFirst())?.n ?? 0;
  return {
    key_ready: !!s,
    connected: !!s?.token,
    server_name: s?.server_name ?? "",
    abm_org_name: s?.abm_org_name ?? "",
    token_expires_at: isoOrNull(s?.token_expires_at ?? null),
    devices: Number(n),
    last_sync_at: isoOrNull(s?.last_sync_at ?? null),
    last_error: s?.last_error ?? "",
    profile: s?.profile_uuid ? (s.profile as Partial<ProfileIn>) : null,
    enroll_url: s?.token ? enrollUrl(deps, s.enroll_secret) : null,
  };
}

export function registerAdeRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/apple-mdm/ade", tags: ["Apple MDM"], summary: "Apple Business Manager connection", security: bearer, responses: { 200: json(Status), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const deps = c.get("deps");
      return c.json(await deps.db.tenant(p.orgId, (tx) => status(tx, deps, p.orgId)), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apple-mdm/ade/public-key",
      tags: ["Apple MDM"],
      summary: "Make the key for Apple Business Manager and get its public certificate",
      description: "Upload the returned certificate (.pem) in Apple Business Manager when you add or edit this MDM server; ABM encrypts the server token to it. Making a new key disconnects the current token.",
      security: bearer,
      responses: { 200: json(z.object({ certificate: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
        const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: randomBytes(8).toString("hex").replace(/^[89a-f]/, "1"), name: "CN=Votal Nexus MDM (Apple Business Manager)", notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 5 * 365 * 86_400_000), signingAlgorithm: ALG, keys });
        const certPem = cert.toString("pem") + "\n";
        const key = deps.sealer.seal(Buffer.from(pem("PRIVATE KEY", await webcrypto.subtle.exportKey("pkcs8", keys.privateKey))), keyAad(p.orgId));
        await tx
          .insertInto("apple_ade_settings")
          .values({ org_id: p.orgId, key, cert: certPem, enroll_secret: randomBytes(24).toString("base64url"), profile: "{}" })
          .onConflict((oc) => oc.column("org_id").doUpdateSet({ key, cert: certPem, token: null, cursor: null, updated_at: new Date() }))
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.ade_key_created", target: { type: "organization", id: p.orgId } });
        return { certificate: certPem };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/apple-mdm/ade/token",
      tags: ["Apple MDM"],
      summary: "Connect with the server token from Apple Business Manager",
      description: "The .p7m file's contents. Nexus opens it with its key, checks it with Apple, defines its enrollment profile and syncs the Macs assigned to this server.",
      security: bearer,
      request: body(z.object({ token: z.string().min(50).max(200_000), profile: ProfileIn.default({} as ProfileIn) })),
      responses: { 200: json(Status), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const s = await tx.selectFrom("apple_ade_settings").select(["key"]).where("org_id", "=", p.orgId).executeTakeFirst();
        if (!s) throw badRequest("no_key", "Make Nexus's key first, and upload its certificate to Apple Business Manager");
        let token: DepToken;
        try {
          token = openServerToken(input.token, deps.sealer.open(s.key, keyAad(p.orgId)).toString());
        } catch (e) {
          throw badRequest("invalid_token", (e as Error).message);
        }
        let account: { server_name: string; org_name: string };
        try {
          account = await new DepClient(deps.cfg.appleDepBase, token).account();
        } catch (e) {
          throw new ApiError(502, "ade_refused", (e as Error).message);
        }
        await tx
          .updateTable("apple_ade_settings")
          .set({ token: deps.sealer.seal(Buffer.from(JSON.stringify(token)), tokenAad(p.orgId)), token_expires_at: token.access_token_expiry ? new Date(token.access_token_expiry) : null, server_name: account.server_name ?? "", abm_org_name: account.org_name ?? "", cursor: null, last_error: "", updated_at: new Date() })
          .where("org_id", "=", p.orgId)
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.ade_connected", target: { type: "organization", id: p.orgId }, details: { server_name: account.server_name, org_name: account.org_name, expires: token.access_token_expiry } });
        await syncAde(tx, deps, p.orgId, c.get("meta"));
        await defineProfile(tx, deps, p.orgId, input.profile);
        return status(tx, deps, p.orgId);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "put", path: "/v1/apple-mdm/ade/profile", tags: ["Apple MDM"], summary: "Change the Setup Assistant enrollment profile", security: bearer, request: body(ProfileIn), responses: { 200: json(Status), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const uuid = await defineProfile(tx, deps, p.orgId, input);
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.ade_profile_changed", target: { type: "organization", id: p.orgId }, details: { ...input, profile_uuid: uuid } });
        return status(tx, deps, p.orgId);
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "post", path: "/v1/apple-mdm/ade/sync", tags: ["Apple MDM"], summary: "Sync Macs from Apple Business Manager now", security: bearer, responses: { 200: json(z.object({ changes: z.number().int(), assigned: z.number().int() })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const deps = c.get("deps");
      return c.json(await deps.db.tenant(p.orgId, (tx) => syncAde(tx, deps, p.orgId, c.get("meta"))), 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/apple-mdm/ade/devices",
      tags: ["Apple MDM"],
      summary: "Macs assigned to Nexus in Apple Business Manager",
      security: bearer,
      responses: {
        200: json(z.object({ data: z.array(z.object({ serial: z.string(), model: z.string(), description: z.string(), color: z.string(), profile_status: z.string(), enrolled: z.boolean(), updated_at: z.string() })) })),
        ...problemResponses,
      },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const rows = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const list = await tx.selectFrom("apple_ade_devices").selectAll().where("deleted", "=", false).orderBy("serial").execute();
        const enrolled = new Set((await tx.selectFrom("apple_mdm_devices").select("serial").where("status", "=", "enrolled").execute()).map((d) => d.serial));
        return list.map((d) => ({ serial: d.serial, model: d.model, description: d.description, color: d.color, profile_status: d.profile_status, enrolled: enrolled.has(d.serial), updated_at: iso(d.updated_at) }));
      });
      return c.json({ data: rows }, 200);
    },
  );

  // Setup Assistant: the Mac posts its machine info (CMS signed by the device) and gets its profile.
  app.post("/mdm/apple/ade/:secret/enroll", async (c) => {
    const deps = c.get("deps");
    const meta = c.get("meta");
    const org = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_apple_ade_org(${c.req.param("secret")})`.execute(tx)).rows[0]);
    if (!org) throw new ApiError(404, "not_found", "Unknown enrollment URL");
    let info: Record<string, unknown>;
    try {
      const { content } = openSignedContent(Buffer.from(await c.req.arrayBuffer()));
      info = plist.parse(content.toString("utf8")) as Record<string, unknown>;
    } catch (e) {
      throw new ApiError(400, "bad_machine_info", e instanceof SignatureError ? e.message : "The machine info isn't a signed property list");
    }
    const serial = typeof info.SERIAL === "string" ? info.SERIAL : "";
    const profile = await deps.db.tenant(org.org_id, async (tx) => {
      const known = await tx.selectFrom("apple_ade_devices").select("serial").where("serial", "=", serial).where("deleted", "=", false).executeTakeFirst();
      if (!known) throw new ApiError(403, "not_assigned", "This Mac isn't assigned to this organization in Apple Business Manager");
      return issueProfile(tx, deps, org.org_id, null, meta, { actor: `Setup Assistant (${serial})`, target: { type: "apple_ade_device", id: org.org_id, display: serial } });
    });
    return new Response(new Uint8Array(profile), { headers: { "content-type": "application/x-apple-aspen-config", "cache-control": "no-store" } });
  });
}

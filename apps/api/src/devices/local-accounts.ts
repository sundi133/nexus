import { createCipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import type { App, Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { assertDeviceInScope, assertUserInScope, requirePermission, requireRecentMfa, requireSession, scopeOf } from "../auth/guard.js";
import type { Principal } from "../context.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { isUniqueViolation } from "../platform/db.js";
import { badRequest, conflict, forbidden, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { commandKey, sign } from "./commands.js";

/**
 * Laptop sign-in with the company account (like JumpCloud user binding and password sync).
 *
 * Admins give people a local account on devices, optionally with admin rights. The account goes
 * to the agent in the signed device policy; a suspended or offboarded person's account is
 * disabled there. Nexus stores only password hashes, so it can't hand a device a password
 * later: it sends one at the moments it sees it (a sign-in to Nexus, a password change or
 * reset), encrypted to each bound device's own X25519 key and signed with the organization's
 * command key. The server never stores the plaintext, and the envelope is gone once the device
 * has set the password. A keyed fingerprint tells a sign-in with a changed password (say, one
 * changed in Active Directory) from one with the same password, so it isn't sent again.
 */

export const SECRET_TYP = "nexus-secret+jwt";
const DELIVERY_TTL_MS = 30 * 24 * 3600_000;
const ENVELOPE_TTL_S = 3600;
const INFO = "nexus-password-v1";

/** Encrypts a password to a device (the agent's accounts.Open is the other side). */
export function sealForDevice(devicePub: string, deviceId: string, userId: string, version: number, secret: { password: string; old?: string }) {
  const dev = Buffer.from(devicePub, "base64url");
  const eph = generateKeyPairSync("x25519");
  const ephPub = Buffer.from(eph.publicKey.export({ format: "jwk" }).x!, "base64url");
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: createPublicKey({ key: { kty: "OKP", crv: "X25519", x: devicePub }, format: "jwk" }) });
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephPub, dev]), INFO, 32));
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(Buffer.from(`${deviceId}|${userId}|${version}`));
  const ct = Buffer.concat([c.update(JSON.stringify(secret)), c.final(), c.getAuthTag()]);
  return Buffer.concat([ephPub, nonce, ct]).toString("base64url");
}

/**
 * Called wherever Nexus sees a person's password in the clear and has checked it: sends it on to
 * the devices they have an account on. Does nothing for people without local accounts.
 */
export async function capturePassword(tx: Tx, deps: Pick<Deps, "sealer">, userId: string, password: string, old?: string) {
  const bindings = await tx
    .selectFrom("device_accounts")
    .innerJoin("devices", "devices.id", "device_accounts.device_id")
    .select(["device_accounts.device_id", "device_accounts.password_version", "devices.enc_public_key", "devices.org_id"])
    .where("device_accounts.user_id", "=", userId)
    .where("devices.status", "=", "active")
    .execute();
  if (!bindings.length) return;
  const u = await tx.selectFrom("users").select(["local_password_version", "local_password_fp"]).where("id", "=", userId).executeTakeFirst();
  if (!u) return;
  const fp = deps.sealer.fingerprint(`${userId}\0${password}`, "local-password");
  let version = u.local_password_version;
  const changed = fp !== u.local_password_fp;
  if (changed) {
    version += 1;
    await tx.updateTable("users").set({ local_password_version: version, local_password_fp: fp }).where("id", "=", userId).execute();
  }
  const pending = new Map((await tx.selectFrom("password_deliveries").select(["device_id", "version"]).where("user_id", "=", userId).execute()).map((d) => [d.device_id, d.version]));
  for (const b of bindings) {
    if (!b.enc_public_key || b.password_version >= version || (pending.get(b.device_id) ?? 0) >= version) continue;
    const ciphertext = sealForDevice(b.enc_public_key, b.device_id, userId, version, { password, ...(changed && old ? { old } : {}) });
    const expires_at = new Date(Date.now() + DELIVERY_TTL_MS);
    await tx
      .insertInto("password_deliveries")
      .values({ org_id: b.org_id, device_id: b.device_id, user_id: userId, version, ciphertext, expires_at })
      .onConflict((oc) => oc.columns(["device_id", "user_id"]).doUpdateSet({ version, ciphertext, created_at: new Date(), expires_at }))
      .execute();
  }
}

export type PolicyAccount = { user_id: string; username: string; full_name: string; admin: boolean; state: "active" | "disabled"; take_over: boolean; password_version: number };

/** The local accounts in a device's signed policy. */
export async function accountsFor(tx: Tx, device: { id: string }): Promise<PolicyAccount[]> {
  const rows = await tx
    .selectFrom("device_accounts")
    .innerJoin("users", "users.id", "device_accounts.user_id")
    .select(["device_accounts.user_id", "device_accounts.username", "device_accounts.admin", "device_accounts.take_over", "users.given_name", "users.family_name", "users.email", "users.status", "users.local_password_version"])
    .where("device_accounts.device_id", "=", device.id)
    .orderBy("device_accounts.username")
    .execute();
  return rows.map((r) => ({
    user_id: r.user_id,
    username: r.username,
    full_name: `${r.given_name} ${r.family_name}`.trim() || r.email,
    admin: r.admin && r.status === "active",
    state: r.status === "active" ? "active" : "disabled",
    take_over: r.take_over,
    password_version: r.local_password_version,
  }));
}

/** Passwords waiting for this device, as envelopes signed for it. */
export async function passwordsFor(tx: Tx, deps: Deps, device: { id: string; org_id: string }): Promise<string[]> {
  await tx.deleteFrom("password_deliveries").where("device_id", "=", device.id).where("expires_at", "<", new Date()).execute();
  const rows = await tx
    .selectFrom("password_deliveries")
    .innerJoin("users", "users.id", "password_deliveries.user_id")
    .innerJoin("device_accounts", (j) => j.onRef("device_accounts.device_id", "=", "password_deliveries.device_id").onRef("device_accounts.user_id", "=", "password_deliveries.user_id"))
    .select(["password_deliveries.user_id", "password_deliveries.version", "password_deliveries.ciphertext"])
    .where("password_deliveries.device_id", "=", device.id)
    .where("users.status", "=", "active")
    .limit(50)
    .execute();
  if (!rows.length) return [];
  const key = await commandKey(tx, deps, device.org_id);
  const exp = Math.floor(Date.now() / 1000) + ENVELOPE_TTL_S;
  return Promise.all(rows.map((r) => sign(key.privatePem, { sub: device.id, uid: r.user_id, ver: r.version, ct: r.ciphertext, exp }, SECRET_TYP)));
}

export const AccountsReport = z
  .array(
    z.object({
      user_id: z.string().max(64),
      username: z.string().max(64),
      status: z.enum(["active", "waiting_password", "disabled", "failed"]),
      password_version: z.number().int().min(0),
      detail: z.string().max(500).default(""),
    }),
  )
  .max(200);

/** What the agent says about each account; delivered passwords it has set are dropped. */
export async function recordAccounts(tx: Tx, device: { id: string; org_id: string; hostname: string }, rep: z.infer<typeof AccountsReport>, meta: RequestMeta) {
  const bound = new Map((await tx.selectFrom("device_accounts").select(["user_id", "username", "status", "detail", "password_version"]).where("device_id", "=", device.id).execute()).map((b) => [b.user_id, b]));
  for (const r of rep) {
    const b = bound.get(r.user_id);
    if (!b || b.username !== r.username) continue;
    await tx.deleteFrom("password_deliveries").where("device_id", "=", device.id).where("user_id", "=", r.user_id).where("version", "<=", r.password_version).execute();
    if (b.status === r.status && b.detail === r.detail && b.password_version === r.password_version) continue;
    await tx.updateTable("device_accounts").set({ status: r.status, detail: r.detail, password_version: r.password_version, reported_at: new Date() }).where("device_id", "=", device.id).where("user_id", "=", r.user_id).execute();
    const type =
      r.status === "failed" && b.status !== "failed"
        ? "device.local_account_failed"
        : r.password_version > b.password_version
          ? "device.local_password_synced"
          : r.status !== b.status && (r.status === "active" || r.status === "disabled")
            ? `device.local_account_${r.status === "active" ? "enabled" : "disabled"}`
            : null;
    if (!type) continue;
    await audit(tx, device.org_id, { meta }, {
      type,
      outcome: r.status === "failed" ? "failure" : "success",
      actor: { type: "system", id: null, display: "Nexus agent" },
      target: { type: "device", id: device.id, display: device.hostname },
      details: { user_id: r.user_id, username: r.username, status: r.status, password_version: r.password_version, detail: r.detail },
    });
  }
}

/** A device's reported key changed (reinstall): envelopes sealed to the old one are useless. */
export async function storeEncKey(tx: Tx, device: { id: string }, key: string) {
  const cur = await tx.selectFrom("devices").select("enc_public_key").where("id", "=", device.id).executeTakeFirst();
  if (cur?.enc_public_key === key) return;
  await tx.updateTable("devices").set({ enc_public_key: key }).where("id", "=", device.id).execute();
  await tx.deleteFrom("password_deliveries").where("device_id", "=", device.id).execute();
}

/** The account name to suggest: the email's local part, as the OSes allow. */
export function suggestUsername(email: string) {
  const base = email.split("@")[0]!.toLowerCase().replace(/[^a-z0-9._-]/g, "").replace(/^[^a-z]+/, "");
  return base.slice(0, 20).replace(/\.+$/, "") || "user";
}

const RESERVED = new Set(["root", "admin", "administrator", "guest", "daemon", "nobody", "bin", "sys", "sync", "defaultaccount", "wdagutilityaccount", "nexus", "sshd", "www-data", "messagebus", "operator", "games", "mail"]);
const Username = z
  .string()
  .regex(/^[a-z][a-z0-9._-]{0,19}$/, "Lower-case letters, digits, dots, dashes and underscores; starts with a letter; up to 20 characters")
  .refine((u) => !RESERVED.has(u) && !u.startsWith("systemd-") && !u.endsWith("."), "That's a system account name");

/** Local admin rights make someone root on the device: the same bar as running scripts there. */
const canGrantAdmin = (p: Principal) => scopeOf(p, "devices:scripts") === "all";

const AccountOut = z
  .object({
    user_id: Id,
    email: z.string(),
    name: z.string(),
    username: z.string(),
    admin: z.boolean(),
    take_over: z.boolean(),
    status: z.enum(["pending", "waiting_password", "active", "disabled", "failed"]),
    detail: z.string(),
    password_synced: z.boolean().openapi({ description: "The device has the person's current Nexus password" }),
    reported_at: z.string().nullable(),
    created_at: z.string(),
  })
  .openapi("DeviceAccount");

async function listAccounts(tx: Tx, deviceId: string) {
  const rows = await tx
    .selectFrom("device_accounts")
    .innerJoin("users", "users.id", "device_accounts.user_id")
    .select(["device_accounts.user_id", "device_accounts.username", "device_accounts.admin", "device_accounts.take_over", "device_accounts.status", "device_accounts.detail", "device_accounts.password_version", "device_accounts.reported_at", "device_accounts.created_at", "users.email", "users.given_name", "users.family_name", "users.local_password_version"])
    .where("device_accounts.device_id", "=", deviceId)
    .orderBy("device_accounts.username")
    .execute();
  return rows.map((r) => ({
    user_id: r.user_id,
    email: r.email,
    name: `${r.given_name} ${r.family_name}`.trim() || r.email,
    username: r.username,
    admin: r.admin,
    take_over: r.take_over,
    status: r.status,
    detail: r.detail,
    password_synced: r.local_password_version > 0 && r.password_version >= r.local_password_version,
    reported_at: isoOrNull(r.reported_at),
    created_at: iso(r.created_at),
  }));
}

export function registerLocalAccountRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/devices/{id}/accounts", tags: ["Devices"], summary: "People's local accounts on a device", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 200: json(z.object({ data: z.array(AccountOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const { id } = c.req.valid("param");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        await assertDeviceInScope(tx, p, "devices:read", id);
        return listAccounts(tx, id);
      });
      return c.json({ data: out }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/devices/{id}/accounts/{user_id}",
      tags: ["Devices"],
      summary: "Give a person a local account on a device, or change it",
      description:
        "The agent creates the account (locked until the person signs in to Nexus, which sends their password encrypted to the device), or with `take_over` manages an existing one. Admin rights make the person root on that device, so they need `devices:scripts` as well as `devices:write`. Needs a recent MFA.",
      security: bearer,
      request: { params: z.object({ id: Id, user_id: Id }), ...body(z.object({ username: Username.optional().openapi({ description: "Default: from the email address" }), admin: z.boolean().default(false), take_over: z.boolean().default(false) })) },
      responses: { 200: json(AccountOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write", { scoped: true });
      const { id, user_id } = c.req.valid("param");
      const input = c.req.valid("json");
      if (input.admin && !canGrantAdmin(p)) throw forbidden("Local admin rights make someone root on the device: only owners and admins can grant them");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        await assertDeviceInScope(tx, p, "devices:write", id);
        await assertUserInScope(tx, p, "devices:write", user_id);
        const d = await tx.selectFrom("devices").select(["hostname", "status"]).where("id", "=", id).executeTakeFirst();
        if (!d || d.status !== "active") throw notFound("Device");
        const u = await tx.selectFrom("users").select(["email", "status"]).where("id", "=", user_id).executeTakeFirst();
        if (!u) throw notFound("User");
        const cur = await tx.selectFrom("device_accounts").select(["username", "admin"]).where("device_id", "=", id).where("user_id", "=", user_id).executeTakeFirst();
        if (cur?.admin && !input.admin && !canGrantAdmin(p)) throw forbidden("Only owners and admins can change local admin rights");
        const username = input.username ?? cur?.username ?? suggestUsername(u.email);
        if (!Username.safeParse(username).success) throw badRequest("invalid_username", `Choose an account name: "${username}" can't be used`);
        try {
          await tx
            .insertInto("device_accounts")
            .values({ id: newId(), org_id: p.orgId, device_id: id, user_id, username, admin: input.admin, take_over: input.take_over, created_by: p.userId })
            .onConflict((oc) => oc.columns(["device_id", "user_id"]).doUpdateSet({ username, admin: input.admin, take_over: input.take_over }))
            .execute();
        } catch (e) {
          if (isUniqueViolation(e)) throw conflict("username_taken", `Someone else already has the account ${username} on ${d.hostname}`);
          throw e;
        }
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, {
          type: cur ? "device.local_account_changed" : "device.local_account_bound",
          target: { type: "device", id, display: d.hostname },
          details: { user_id, email: u.email, username, admin: input.admin, take_over: input.take_over, ...(cur ? { before: { username: cur.username, admin: cur.admin } } : {}) },
        });
        return (await listAccounts(tx, id)).find((a) => a.user_id === user_id)!;
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "delete",
      path: "/v1/devices/{id}/accounts/{user_id}",
      tags: ["Devices"],
      summary: "Stop managing a person's local account (the agent disables it; files stay)",
      security: bearer,
      request: { params: z.object({ id: Id, user_id: Id }) },
      responses: { 204: { description: "Removed" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write", { scoped: true });
      const { id, user_id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        await assertDeviceInScope(tx, p, "devices:write", id);
        const r = await tx.deleteFrom("device_accounts").where("device_id", "=", id).where("user_id", "=", user_id).returning(["username", "admin"]).executeTakeFirst();
        if (!r) throw notFound("Account");
        if (r.admin && !canGrantAdmin(p)) throw forbidden("Only owners and admins can remove a local admin");
        await tx.deleteFrom("password_deliveries").where("device_id", "=", id).where("user_id", "=", user_id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.local_account_unbound", target: { type: "device", id }, details: { user_id, username: r.username } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/me/device-accounts",
      tags: ["Me"],
      summary: "Your accounts on devices, and whether they have your current password",
      security: bearer,
      responses: { 200: json(z.object({ data: z.array(z.object({ device_id: Id, hostname: z.string(), platform: z.string(), username: z.string(), admin: z.boolean(), status: z.string(), password_synced: z.boolean(), detail: z.string() })) })), ...problemResponses },
    }),
    async (c) => {
      const p = requireSession(c);
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const v = (await tx.selectFrom("users").select("local_password_version").where("id", "=", p.userId).executeTakeFirstOrThrow()).local_password_version;
        const rows = await tx
          .selectFrom("device_accounts")
          .innerJoin("devices", "devices.id", "device_accounts.device_id")
          .select(["device_accounts.device_id", "devices.hostname", "devices.platform", "device_accounts.username", "device_accounts.admin", "device_accounts.status", "device_accounts.password_version", "device_accounts.detail"])
          .where("device_accounts.user_id", "=", p.userId)
          .where("devices.status", "=", "active")
          .orderBy("devices.hostname")
          .execute();
        return rows.map((r) => ({ device_id: r.device_id, hostname: r.hostname, platform: r.platform, username: r.username, admin: r.admin, status: r.status, password_synced: v > 0 && r.password_version >= v, detail: r.detail }));
      });
      return c.json({ data: out }, 200);
    },
  );
}


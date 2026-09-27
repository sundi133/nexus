import { randomBytes } from "node:crypto";
import { sql } from "kysely";
import { bodyLimit } from "hono/body-limit";
import plist from "plist";
import type { App, Deps, RequestMeta } from "../context.js";
import { audit } from "../audit/record.js";
import { hashToken } from "../auth/tokens.js";
import type { Tx } from "../platform/db.js";
import { ApiError } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { ensureCa, issueIdentity, pkcs12, SignatureError, verifyMdmSignature } from "./pki.js";
import { enrollmentProfile, platformOf, queueCommand } from "./service.js";
import { profileResult, reconcileProfiles } from "./profiles.js";

/**
 * The Apple MDM protocol, as a Mac speaks it:
 *  - GET  /mdm/apple/enroll/{token}: the enrollment profile, with a fresh device identity.
 *  - PUT  /mdm/apple/checkin: Authenticate, TokenUpdate, CheckOut, bootstrap token.
 *  - PUT  /mdm/apple/connect: results of the last command, and the next one.
 * Every check-in and connect must be signed (Mdm-Signature) by an identity Nexus issued; the
 * signer is also bound to the device's UDID, so one enrolled Mac can't speak for another.
 */

const PLIST = { "content-type": "application/xml; charset=utf-8" };
const deviceActor = (name: string) => ({ type: "system" as const, id: null, display: name || "Mac (MDM)" });
type Msg = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" ? v : "");

function parsePlist(body: Buffer): Msg {
  try {
    const v = plist.parse(body.toString("utf8"));
    if (v && typeof v === "object" && !Array.isArray(v)) return v as Msg;
  } catch {}
  throw new ApiError(400, "bad_plist", "Body must be a property list");
}

/** Who is speaking: the org that issued the signing identity, and its fingerprint. */
async function signer(deps: Deps, body: Buffer, header: string | undefined) {
  let fp: string;
  try {
    fp = verifyMdmSignature(body, header).fingerprint;
  } catch (e) {
    if (e instanceof SignatureError) throw new ApiError(401, "bad_signature", e.message);
    throw e;
  }
  const org = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT * FROM nexus_apple_mdm_identity(${fp})`.execute(tx)).rows[0]);
  if (!org) throw new ApiError(401, "unknown_identity", "This identity wasn't issued by Nexus");
  return { orgId: org.org_id, fp };
}

/** The device this identity is for; anything else is refused. */
async function boundDevice(tx: Tx, udid: string, fp: string) {
  const d = await tx.selectFrom("apple_mdm_devices").selectAll().where("udid", "=", udid).executeTakeFirst();
  if (!d || d.identity_fp !== fp) throw new ApiError(401, "not_enrolled", "This device isn't enrolled with this identity");
  return d;
}

const META = (m: RequestMeta) => ({ meta: m });

async function linkAgentDevice(tx: Tx, mdmId: string, serial: string) {
  if (!serial) return;
  const agent = await tx.selectFrom("devices").select("id").where("serial", "=", serial).where("status", "=", "active").executeTakeFirst();
  if (agent) await tx.updateTable("apple_mdm_devices").set({ device_id: agent.id }).where("id", "=", mdmId).execute();
}

/** A fresh device identity and the enrollment profile carrying it (enrollment links and ADE). */
export async function issueProfile(tx: Tx, deps: Deps, orgId: string, linkId: string | null, meta: RequestMeta, who: { actor: string; target: { type: string; id: string; display?: string } }) {
  const s = await tx.selectFrom("apple_mdm_settings").select(["push_topic"]).where("org_id", "=", orgId).executeTakeFirst();
  if (!s?.push_topic) throw new ApiError(409, "mdm_not_ready", "Device management isn't set up yet: an admin must add the Apple push certificate first.");
  const { name } = await tx.selectFrom("organizations").select("name").where("id", "=", orgId).executeTakeFirstOrThrow();
  const ca = await ensureCa(tx, deps, orgId);
  const identity = await issueIdentity(ca, `Nexus MDM ${randomBytes(6).toString("hex")}`);
  const password = randomBytes(18).toString("base64url");
  await tx.insertInto("apple_mdm_identities").values({ fingerprint: identity.fingerprint, org_id: orgId, link_id: linkId }).execute();
  await audit(tx, orgId, META(meta), { type: "apple_mdm.profile_downloaded", actor: { type: "system", id: null, display: who.actor }, target: who.target, details: { identity: identity.fingerprint.slice(0, 16) } });
  return enrollmentProfile({ orgName: name, orgId, apiUrl: deps.cfg.apiPublicUrl, topic: s.push_topic, p12: pkcs12(identity, ca.certPem, password), p12Password: password });
}

export function registerAppleMdmProtocol(app: App) {
  // Devices aren't authenticated until the signature is checked: cap bodies first (app lists can be large).
  app.use("/mdm/apple/*", bodyLimit({ maxSize: 4 * 1024 * 1024, onError: () => { throw new ApiError(413, "payload_too_large", "Request body is too large"); } }));

  app.get("/mdm/apple/enroll/:token", async (c) => {
    const deps = c.get("deps");
    const meta = c.get("meta");
    const link = await deps.db.unscoped(async (tx) => (await sql<{ org_id: string; link_id: string }>`SELECT * FROM nexus_apple_mdm_link(${hashToken(c.req.param("token"))})`.execute(tx)).rows[0]);
    if (!link) throw new ApiError(404, "link_invalid", "This enrollment link is invalid, expired or revoked. Ask IT for a new one.");
    const profile = await deps.db.tenant(link.org_id, async (tx) => {
      await tx.updateTable("apple_mdm_enroll_links").set((eb) => ({ uses: eb("uses", "+", 1) })).where("id", "=", link.link_id).execute();
      return issueProfile(tx, deps, link.org_id, link.link_id, meta, { actor: `Enrollment link from ${meta.ip || "unknown address"}`, target: { type: "apple_mdm_link", id: link.link_id } });
    });
    return new Response(new Uint8Array(profile), { headers: { "content-type": "application/x-apple-aspen-config", "content-disposition": 'attachment; filename="Nexus device management.mobileconfig"', "cache-control": "no-store" } });
  });

  app.put("/mdm/apple/checkin", async (c) => {
    const deps = c.get("deps");
    const meta = c.get("meta");
    const body = Buffer.from(await c.req.arrayBuffer());
    const { orgId, fp } = await signer(deps, body, c.req.header("mdm-signature"));
    const m = parsePlist(body);
    const type = str(m.MessageType);
    const udid = str(m.UDID);
    if (m.UserID || m.UserShortName) return c.body(null, 200); // user channel: not managed yet
    if (!udid && type !== "UserAuthenticate") throw new ApiError(400, "no_udid", "UDID is required");

    const out = await deps.db.tenant(orgId, async (tx): Promise<Msg | null> => {
      switch (type) {
        case "Authenticate": {
          const s = await tx.selectFrom("apple_mdm_settings").select("push_topic").where("org_id", "=", orgId).executeTakeFirst();
          if (str(m.Topic) !== s?.push_topic) throw new ApiError(400, "wrong_topic", "The profile's push topic isn't this organization's");
          const fields = {
            identity_fp: fp,
            serial: str(m.SerialNumber),
            model: str(m.ModelName) || str(m.Model),
            os_version: str(m.OSVersion),
            device_name: str(m.DeviceName),
            topic: str(m.Topic),
            platform: platformOf(str(m.ProductName), str(m.Model)),
            last_seen_at: new Date(),
          };
          await tx
            .insertInto("apple_mdm_devices")
            .values({ id: newId(), org_id: orgId, udid, ...fields, status: "authenticated", info: "{}", security: "{}" })
            .onConflict((oc) => oc.columns(["org_id", "udid"]).doUpdateSet({ ...fields, status: "authenticated" }))
            .execute();
          return null;
        }
        case "TokenUpdate": {
          const d = await boundDevice(tx, udid, fp);
          const token = Buffer.isBuffer(m.Token) ? m.Token.toString("hex") : "";
          if (!token || !str(m.PushMagic)) throw new ApiError(400, "no_token", "Token and PushMagic are required");
          const first = d.status !== "enrolled";
          await tx
            .updateTable("apple_mdm_devices")
            .set({
              push_token: token,
              push_magic: str(m.PushMagic),
              ...(Buffer.isBuffer(m.UnlockToken) ? { unlock_token: deps.sealer.seal(m.UnlockToken, `apple_mdm_unlock:${d.id}`) } : {}),
              status: "enrolled",
              enrolled_at: d.enrolled_at ?? new Date(),
              last_seen_at: new Date(),
            })
            .where("id", "=", d.id)
            .execute();
          if (first) {
            await linkAgentDevice(tx, d.id, d.serial);
            await queueCommand(tx, orgId, d.id, "DeviceInformation", { Queries: ["DeviceName", "OSVersion", "BuildVersion", "ModelName", "Model", "ProductName", "SerialNumber"] }, { userId: null, reason: "Enrolled" });
            await queueCommand(tx, orgId, d.id, "SecurityInfo", {}, { userId: null, reason: "Enrolled" });
            await reconcileProfiles(tx, deps, orgId, [d.id]);
            await audit(tx, orgId, META(meta), { type: "apple_mdm.enrolled", actor: deviceActor(d.device_name), target: { type: "apple_mdm_device", id: d.id, display: d.device_name || d.serial }, details: { serial: d.serial, model: d.model, os_version: d.os_version } });
          }
          return null;
        }
        case "CheckOut": {
          const d = await boundDevice(tx, udid, fp);
          await tx.updateTable("apple_mdm_devices").set({ status: "checked_out", push_token: null, push_magic: null, last_seen_at: new Date() }).where("id", "=", d.id).execute();
          await tx.updateTable("apple_mdm_commands").set({ status: "canceled", finished_at: new Date() }).where("mdm_device_id", "=", d.id).where("status", "in", ["queued", "sent", "notnow"]).execute();
          await audit(tx, orgId, META(meta), { type: "apple_mdm.unenrolled", actor: deviceActor(d.device_name), target: { type: "apple_mdm_device", id: d.id, display: d.device_name || d.serial }, details: { serial: d.serial } });
          return null;
        }
        case "SetBootstrapToken": {
          const d = await boundDevice(tx, udid, fp);
          const t = Buffer.isBuffer(m.BootstrapToken) ? m.BootstrapToken : null;
          await tx.updateTable("apple_mdm_devices").set({ bootstrap_token: t ? deps.sealer.seal(t, `apple_mdm_bootstrap:${d.id}`) : null }).where("id", "=", d.id).execute();
          await audit(tx, orgId, META(meta), { type: t ? "apple_mdm.bootstrap_token_escrowed" : "apple_mdm.bootstrap_token_cleared", actor: deviceActor(d.device_name), target: { type: "apple_mdm_device", id: d.id, display: d.device_name || d.serial } });
          return null;
        }
        case "GetBootstrapToken": {
          const d = await boundDevice(tx, udid, fp);
          return d.bootstrap_token ? { BootstrapToken: deps.sealer.open(d.bootstrap_token, `apple_mdm_bootstrap:${d.id}`) } : {};
        }
        case "UserAuthenticate":
          throw new ApiError(410, "no_user_channel", "User channel isn't supported");
        default:
          throw new ApiError(400, "unsupported_message", `Unsupported check-in message ${type}`);
      }
    });
    return out ? c.body(plist.build(out as plist.PlistValue), 200, PLIST) : c.body(null, 200);
  });

  app.put("/mdm/apple/connect", async (c) => {
    const deps = c.get("deps");
    const meta = c.get("meta");
    const body = Buffer.from(await c.req.arrayBuffer());
    const { orgId, fp } = await signer(deps, body, c.req.header("mdm-signature"));
    const m = parsePlist(body);
    if (m.UserID) return c.body(null, 200);
    const next = await deps.db.tenant(orgId, async (tx) => {
      const d = await boundDevice(tx, str(m.UDID), fp);
      if (d.status !== "enrolled") throw new ApiError(401, "not_enrolled", "This device isn't enrolled");
      await tx.updateTable("apple_mdm_devices").set({ last_seen_at: new Date() }).where("id", "=", d.id).execute();
      const status = str(m.Status);
      const uuid = str(m.CommandUUID);
      let skip: string | null = null;
      if (uuid && status !== "Idle") {
        const cmd = await tx.selectFrom("apple_mdm_commands").select(["id", "request_type", "requested_by"]).where("id", "=", uuid).where("mdm_device_id", "=", d.id).executeTakeFirst();
        if (cmd) {
          const { UDID: _u, Status: _s, CommandUUID: _c, ...result } = m;
          const errText = Array.isArray(m.ErrorChain) ? (m.ErrorChain as Msg[]).map((e) => str(e.LocalizedDescription) || str(e.ErrorDomain)).filter(Boolean).join("; ") : "";
          const newStatus = status === "Acknowledged" ? "acknowledged" : status === "NotNow" ? "notnow" : "error";
          await tx
            .updateTable("apple_mdm_commands")
            .set({
              status: newStatus,
              result: JSON.stringify(jsonSafe(result)),
              error: newStatus === "error" ? errText || status : "",
              finished_at: newStatus === "notnow" ? null : new Date(),
              // Once delivered, secrets in the command aren't kept: the lock/erase PIN (shown to the admin
              // once) and a passcode-clearing unlock token.
              ...(newStatus !== "notnow" ? { command: sql`(CASE WHEN command ? 'PIN' THEN jsonb_set(command, '{PIN}', '"••••••"') ELSE command END) - 'UnlockToken'` } : {}),
            })
            .where("id", "=", cmd.id)
            .execute();
          if (newStatus === "notnow") skip = cmd.id;
          if (newStatus === "acknowledged") await applyResult(tx, deps, orgId, d.id, cmd.request_type, m);
          if ((cmd.request_type === "InstallProfile" || cmd.request_type === "RemoveProfile") && newStatus !== "notnow") await profileResult(tx, cmd.id, newStatus === "acknowledged", errText || status);
          if (cmd.requested_by) {
            await audit(tx, orgId, META(meta), {
              type: "apple_mdm.command_finished",
              outcome: newStatus === "error" ? "failure" : "success",
              actor: deviceActor(d.device_name),
              target: { type: "apple_mdm_device", id: d.id, display: d.device_name || d.serial },
              details: { command_id: cmd.id, request_type: cmd.request_type, status: newStatus, error: errText },
            });
          }
        }
      }
      // Group membership may have changed since: bring this Mac's profiles up to date while it's here.
      if (status === "Idle") await reconcileProfiles(tx, deps, orgId, [d.id]);
      let q = tx.selectFrom("apple_mdm_commands").select(["id", "command"]).where("mdm_device_id", "=", d.id).where("status", "in", ["queued", "notnow"]).orderBy("created_at").limit(1);
      if (skip) q = q.where("id", "!=", skip); // it just said NotNow: try the rest, and this one next time
      const cmd = await q.executeTakeFirst();
      if (!cmd) return null;
      await tx.updateTable("apple_mdm_commands").set({ status: "sent", sent_at: new Date() }).where("id", "=", cmd.id).execute();
      return { CommandUUID: cmd.id, Command: withData(cmd.command) };
    });
    return next ? c.body(plist.build(next as unknown as plist.PlistValue), 200, PLIST) : c.body(null, 200);
  });
}

/** Results worth keeping on the device record. */
/** Commands are stored as JSON: binary values ({ $data: base64 }) go back to plist data. */
function withData(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(withData);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (typeof o.$data === "string" && Object.keys(o).length === 1) return Buffer.from(o.$data, "base64");
    return Object.fromEntries(Object.entries(o).map(([k, x]) => [k, withData(x)]));
  }
  return v;
}

async function applyResult(tx: Tx, deps: Deps, orgId: string, id: string, type: string, m: Msg) {
  if (type === "EnableLostMode" || type === "DisableLostMode") {
    await tx.updateTable("apple_mdm_devices").set({ lost_mode: type === "EnableLostMode" }).where("id", "=", id).execute();
  }
  if (type === "DeviceInformation" && m.QueryResponses && typeof m.QueryResponses === "object") {
    const q = m.QueryResponses as Msg;
    await tx
      .updateTable("apple_mdm_devices")
      .set({
        ...(str(q.DeviceName) ? { device_name: str(q.DeviceName) } : {}),
        ...(str(q.OSVersion) ? { os_version: str(q.OSVersion) } : {}),
        ...(str(q.ModelName) ? { model: str(q.ModelName) } : {}),
        ...(str(q.SerialNumber) ? { serial: str(q.SerialNumber) } : {}),
        ...(str(q.ProductName) ? { platform: platformOf(str(q.ProductName), str(q.Model)) } : {}),
        info: JSON.stringify(jsonSafe(q)),
      })
      .where("id", "=", id)
      .execute();
    if (str(q.SerialNumber)) {
      await linkAgentDevice(tx, id, str(q.SerialNumber));
      await reconcileProfiles(tx, deps, orgId, [id]); // linked to its user: group-targeted profiles apply now
    }
  }
  if (type === "SecurityInfo" && m.SecurityInfo && typeof m.SecurityInfo === "object") {
    await tx.updateTable("apple_mdm_devices").set({ security: JSON.stringify(jsonSafe(m.SecurityInfo)) }).where("id", "=", id).execute();
  }
}

/** Plist values → JSON (data becomes base64, dates ISO strings). */
function jsonSafe(v: unknown): unknown {
  if (Buffer.isBuffer(v)) return { base64: v.toString("base64") };
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) return v.map(jsonSafe);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, jsonSafe(x)]));
  return v;
}

import { randomBytes } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import type { App } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { hashToken } from "../auth/tokens.js";
import { badRequest, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import type { Permission } from "../rbac.js";
import { certFingerprint, ensureCa, pushCsr, pushKeyAad, readPushCert } from "./pki.js";
import { reconcileProfiles } from "./profiles.js";
import { COMMANDS, needsPin, newPin, queueCommand, REQUEST_TYPES, type RequestType, wake } from "./service.js";

/**
 * Apple MDM in the console: set up the push certificate (Nexus makes the key and CSR; an MDM
 * vendor signs it; Apple issues the certificate), make enrollment links, and send commands to
 * enrolled Macs. Every change is audited; destructive commands need a recent MFA.
 */

const Status = z
  .object({
    ready: z.boolean().openapi({ description: "Macs can enroll: the push certificate is in place" }),
    csr_pending: z.boolean(),
    push: z.object({ topic: z.string(), expires_at: z.string() }).nullable(),
    ca_fingerprint: z.string().nullable(),
    devices: z.object({ enrolled: z.number().int(), total: z.number().int() }),
    enroll_url_base: z.string(),
  })
  .openapi("AppleMdmStatus");

const Link = z.object({ id: Id, name: z.string(), uses: z.number().int(), created_at: z.string(), expires_at: z.string(), revoked: z.boolean() }).openapi("AppleMdmLink");
const Device = z
  .object({
    id: Id,
    device_name: z.string(),
    serial: z.string(),
    model: z.string(),
    os_version: z.string(),
    status: z.enum(["authenticated", "enrolled", "checked_out"]),
    device_id: Id.nullable().openapi({ description: "The same Mac's Nexus agent device, matched by serial" }),
    platform: z.enum(["macos", "ios", "ipados", "other"]),
    assigned_user: z.object({ id: Id, email: z.string() }).nullable().openapi({ description: "Whose iPhone or iPad it is (Macs follow their agent's user)" }),
    lost_mode: z.boolean(),
    passcode: z.boolean().nullable().openapi({ description: "iPhone and iPad: a passcode is set" }),
    supervised: z.boolean().nullable(),
    bootstrap_token: z.boolean(),
    filevault: z.boolean().nullable(),
    enrolled_at: z.string().nullable(),
    last_seen_at: z.string().nullable(),
    pending_commands: z.number().int(),
  })
  .openapi("AppleMdmDevice");
const Command = z
  .object({ id: z.string(), request_type: z.string(), status: z.string(), error: z.string(), reason: z.string(), requested_by: z.string().nullable(), created_at: z.string(), finished_at: z.string().nullable(), result: z.unknown() })
  .openapi("AppleMdmCommand");

export function registerAppleMdmRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/apple-mdm", tags: ["Apple MDM"], summary: "Whether Macs can enroll, and how many have", security: bearer, responses: { 200: json(Status), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        const s = await tx.selectFrom("apple_mdm_settings").selectAll().where("org_id", "=", p.orgId).executeTakeFirst();
        const counts = await tx.selectFrom("apple_mdm_devices").select(["status"]).execute();
        return {
          ready: !!s?.push_topic,
          csr_pending: !!s?.push_key_pending,
          push: s?.push_topic && s.push_expires_at ? { topic: s.push_topic, expires_at: iso(s.push_expires_at) } : null,
          ca_fingerprint: s ? certFingerprint(Buffer.from(s.ca_cert.replace(/-----[^-]+-----|\s/g, ""), "base64")) : null,
          devices: { enrolled: counts.filter((d) => d.status === "enrolled").length, total: counts.length },
          enroll_url_base: `${deps.cfg.apiPublicUrl}/mdm/apple/enroll/`,
        };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apple-mdm/push-csr",
      tags: ["Apple MDM"],
      summary: "Make the key and CSR for the Apple MDM push certificate",
      description: "Returns a PEM CSR. Have it signed by an MDM vendor certificate, upload the result to Apple's Push Certificates Portal, then upload Apple's certificate here. Making a new CSR doesn't affect a certificate already in place until you upload a new one.",
      security: bearer,
      responses: { 200: json(z.object({ csr: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        await ensureCa(tx, deps, p.orgId);
        const { name } = await tx.selectFrom("organizations").select("name").where("id", "=", p.orgId).executeTakeFirstOrThrow();
        const { csrPem, keyPem } = await pushCsr(name);
        // The certificate in use keeps working (with its key) until Apple's new one is uploaded.
        await tx.updateTable("apple_mdm_settings").set({ push_csr: csrPem, push_key_pending: deps.sealer.seal(Buffer.from(keyPem), pushKeyAad(p.orgId)), updated_at: new Date() }).where("org_id", "=", p.orgId).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.push_csr_created", target: { type: "organization", id: p.orgId } });
        return { csr: csrPem };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/apple-mdm/push-cert",
      tags: ["Apple MDM"],
      summary: "Upload the MDM push certificate from Apple",
      security: bearer,
      request: body(z.object({ certificate: z.string().min(100).max(20_000).openapi({ description: "The PEM certificate Apple's Push Certificates Portal issued" }) })),
      responses: { 200: json(Status.pick({ push: true })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "org:manage");
      const deps = c.get("deps");
      const { certificate } = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const s = await tx.selectFrom("apple_mdm_settings").selectAll().where("org_id", "=", p.orgId).executeTakeFirst();
        if (!s?.push_key_pending) throw badRequest("no_csr", "Make a CSR first: the certificate must be issued for Nexus's key");
        const keyPem = deps.sealer.open(s.push_key_pending, pushKeyAad(p.orgId)).toString();
        let info: { topic: string; notAfter: Date };
        try {
          info = readPushCert(certificate, keyPem);
        } catch (e) {
          throw badRequest("invalid_certificate", (e as Error).message);
        }
        // A renewal must keep the topic: enrolled Macs only listen on the one they enrolled with.
        if (s.push_topic && s.push_topic !== info.topic) throw badRequest("topic_changed", `This certificate is for ${info.topic}, but Macs are enrolled on ${s.push_topic}. Renew the existing certificate in Apple's portal instead of creating a new one.`);
        await tx
          .updateTable("apple_mdm_settings")
          .set({ push_cert: certificate, push_key: s.push_key_pending, push_key_pending: null, push_topic: info.topic, push_expires_at: info.notAfter, push_csr: null, updated_at: new Date() })
          .where("org_id", "=", p.orgId)
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.push_cert_uploaded", target: { type: "organization", id: p.orgId }, details: { topic: info.topic, expires_at: iso(info.notAfter), renewal: !!s.push_topic } });
        return { push: { topic: info.topic, expires_at: iso(info.notAfter) } };
      });
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/apple-mdm/enrollment-links", tags: ["Apple MDM"], summary: "Enrollment links", security: bearer, responses: { 200: json(z.object({ data: z.array(Link) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) => tx.selectFrom("apple_mdm_enroll_links").selectAll().orderBy("created_at", "desc").execute());
      return c.json({ data: rows.map((r) => ({ id: r.id, name: r.name, uses: r.uses, created_at: iso(r.created_at), expires_at: iso(r.expires_at), revoked: !!r.revoked_at || r.expires_at < new Date() })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apple-mdm/enrollment-links",
      tags: ["Apple MDM"],
      summary: "Make an enrollment link (shown once)",
      description: "Opening the link on a Mac downloads the enrollment profile; installing it in System Settings enrolls the Mac.",
      security: bearer,
      request: body(z.object({ name: z.string().trim().min(1).max(100), expires_in_days: z.number().int().min(1).max(365).default(30) })),
      responses: { 201: json(Link.extend({ url: z.string() })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const deps = c.get("deps");
      const input = c.req.valid("json");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const s = await tx.selectFrom("apple_mdm_settings").select("push_topic").where("org_id", "=", p.orgId).executeTakeFirst();
        if (!s?.push_topic) throw badRequest("mdm_not_ready", "Add the Apple push certificate first");
        const token = `nxm_${randomBytes(24).toString("base64url")}`;
        const id = newId();
        const expires = new Date(Date.now() + input.expires_in_days * 86_400_000);
        await tx.insertInto("apple_mdm_enroll_links").values({ id, org_id: p.orgId, name: input.name, token_hash: hashToken(token), created_by: p.userId, expires_at: expires }).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.link_created", target: { type: "apple_mdm_link", id, display: input.name }, details: { expires_at: iso(expires) } });
        return { id, name: input.name, uses: 0, created_at: iso(new Date()), expires_at: iso(expires), revoked: false, url: `${deps.cfg.apiPublicUrl}/mdm/apple/enroll/${token}` };
      });
      return c.json(out, 201);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/apple-mdm/enrollment-links/{id}", tags: ["Apple MDM"], summary: "Revoke an enrollment link (enrolled Macs stay enrolled)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Revoked" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.updateTable("apple_mdm_enroll_links").set({ revoked_at: new Date() }).where("id", "=", id).where("revoked_at", "is", null).returning("name").executeTakeFirst();
        if (!r) throw notFound("Link");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.link_revoked", target: { type: "apple_mdm_link", id, display: r.name } });
      });
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/apple-mdm/devices", tags: ["Apple MDM"], summary: "Macs, iPhones and iPads enrolled in Nexus MDM", security: bearer, responses: { 200: json(z.object({ data: z.array(Device) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const out = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const rows = await tx.selectFrom("apple_mdm_devices").leftJoin("users", "users.id", "apple_mdm_devices.assigned_user_id").selectAll("apple_mdm_devices").select("users.email as assigned_email").orderBy("device_name").execute();
        const pending = await tx.selectFrom("apple_mdm_commands").select(["mdm_device_id"]).select((eb) => eb.fn.countAll<number>().as("n")).where("status", "in", ["queued", "sent", "notnow"]).groupBy("mdm_device_id").execute();
        return rows.map((d) => {
          const sec = d.security as { FDE_Enabled?: boolean; PasscodePresent?: boolean };
          const info = d.info as { IsSupervised?: boolean };
          return {
            id: d.id,
            device_name: d.device_name,
            serial: d.serial,
            model: d.model,
            os_version: d.os_version,
            status: d.status,
            device_id: d.device_id,
            platform: d.platform,
            assigned_user: d.assigned_user_id && d.assigned_email ? { id: d.assigned_user_id, email: d.assigned_email } : null,
            lost_mode: d.lost_mode,
            passcode: typeof sec.PasscodePresent === "boolean" ? sec.PasscodePresent : null,
            supervised: typeof info.IsSupervised === "boolean" ? info.IsSupervised : null,
            bootstrap_token: !!d.bootstrap_token,
            filevault: typeof sec.FDE_Enabled === "boolean" ? sec.FDE_Enabled : null,
            enrolled_at: isoOrNull(d.enrolled_at),
            last_seen_at: isoOrNull(d.last_seen_at),
            pending_commands: Number(pending.find((x) => x.mdm_device_id === d.id)?.n ?? 0),
          };
        });
      });
      return c.json({ data: out }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/apple-mdm/devices/{id}/commands",
      tags: ["Apple MDM"],
      summary: "A Mac's MDM commands and their results",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ data: z.array(Command) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const { id } = c.req.valid("param");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx
          .selectFrom("apple_mdm_commands")
          .leftJoin("users", "users.id", "apple_mdm_commands.requested_by")
          .select(["apple_mdm_commands.id", "request_type", "apple_mdm_commands.status", "error", "reason", "apple_mdm_commands.created_at", "finished_at", "result", "users.email"])
          .where("mdm_device_id", "=", id)
          .orderBy("apple_mdm_commands.created_at", "desc")
          .limit(50)
          .execute(),
      );
      return c.json({ data: rows.map((r) => ({ id: r.id, request_type: r.request_type, status: r.status, error: r.error, reason: r.reason, requested_by: r.email, created_at: iso(r.created_at), finished_at: isoOrNull(r.finished_at), result: r.result })) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apple-mdm/devices/{id}/commands",
      tags: ["Apple MDM"],
      summary: "Send an MDM command to a Mac, iPhone or iPad",
      description:
        "Queues the command and wakes the device through APNs. On a Mac, lock and erase return a 6-digit PIN, shown once (a locked Mac asks for it). iPhones and iPads also take ClearPasscode, EnableLostMode (with a message and phone number), DeviceLocation and PlayLostModeSound (in Lost Mode) and DisableLostMode; Lost Mode, restart, shut down and OS updates need a supervised iPhone or iPad. Lock and restart need `devices:actions`, erase needs `devices:wipe` and the serial number typed to confirm, OS updates need `devices:updates`. Anything that changes the Mac needs a recent MFA.",
      security: bearer,
      request: {
        params: z.object({ id: Id }),
        ...body(
          z.object({
            request_type: z.enum(REQUEST_TYPES as [RequestType, ...RequestType[]]),
            reason: z.string().trim().max(500).default(""),
            message: z.string().trim().max(200).optional(),
            phone: z.string().trim().max(40).optional().openapi({ description: "Lock and Lost Mode: a number shown on the screen" }),
            confirm: z.string().max(100).optional(),
          }),
        ),
      },
      responses: { 201: json(z.object({ id: z.string(), pin: z.string().nullable(), push_error: z.string().nullable() })), ...problemResponses },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const p = requirePermission(c, COMMANDS[input.request_type].perm as Permission);
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const readOnly = COMMANDS[input.request_type].perm === "devices:read";
      if (!readOnly && input.reason.length < 3) throw badRequest("reason_required", "Say why (it goes in the audit log)");
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        if (!readOnly) requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const d = await tx.selectFrom("apple_mdm_devices").select(["id", "status", "serial", "device_name", "platform", "unlock_token", "lost_mode"]).where("id", "=", id).executeTakeFirst();
        if (!d) throw notFound("Device");
        if (d.status !== "enrolled") throw badRequest("not_enrolled", "This device isn't enrolled any more");
        const kind = d.platform === "macos" ? "Mac" : d.platform === "ipados" ? "iPad" : "iPhone";
        if (!(COMMANDS[input.request_type].platforms as readonly string[]).includes(d.platform)) throw badRequest("unsupported", `${input.request_type} doesn't apply to ${kind === "Mac" ? "a Mac" : `an ${kind}`}`);
        if (input.request_type === "EraseDevice" && input.confirm?.trim() !== d.serial) throw badRequest("confirm_mismatch", `Type the ${kind}'s serial number (${d.serial}) to confirm the erase`);
        if ((input.request_type === "DeviceLocation" || input.request_type === "PlayLostModeSound") && !d.lost_mode) throw badRequest("not_lost", `Put the ${kind} in Lost Mode first: Apple only reports its location, or plays the sound, in Lost Mode`);
        // Clearing a passcode needs the unlock token the device escrowed at enrollment.
        let unlockToken: string | undefined;
        if (input.request_type === "ClearPasscode") {
          if (!d.unlock_token) throw badRequest("no_unlock_token", `This ${kind} didn't escrow an unlock token, so its passcode can't be cleared remotely`);
          unlockToken = deps.sealer.open(d.unlock_token, `apple_mdm_unlock:${d.id}`).toString("base64");
        }
        const pin = needsPin(input.request_type, d.platform) ? newPin() : null;
        const fields = (COMMANDS[input.request_type].build as (o: { pin: string; message?: string; phone?: string; unlockToken?: string }) => Record<string, unknown>)({
          pin: pin ?? "",
          message: input.message,
          phone: input.phone,
          unlockToken,
        });
        const cid = await queueCommand(tx, p.orgId, d.id, input.request_type, fields, { userId: p.userId, reason: input.reason });
        if (!readOnly) {
          await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.command_sent", target: { type: "apple_mdm_device", id: d.id, display: d.device_name || d.serial }, details: { command_id: cid, request_type: input.request_type, reason: input.reason } });
        }
        return { id: cid, pin };
      });
      const push_error = await wake(deps, p.orgId, id);
      return c.json({ ...out, push_error }, 201);
    },
  );

  app.openapi(
    createRoute({
      method: "put",
      path: "/v1/apple-mdm/devices/{id}/user",
      tags: ["Apple MDM"],
      summary: "Say whose iPhone or iPad this is (profiles for their groups follow)",
      description: "Macs usually get their person from the Nexus agent; phones and tablets have no agent. `user_id: null` clears it.",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ user_id: Id.nullable() })) },
      responses: { 204: { description: "Assigned" }, ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:write");
      const { id } = c.req.valid("param");
      const { user_id } = c.req.valid("json");
      const deps = c.get("deps");
      const touched = await deps.db.tenant(p.orgId, async (tx) => {
        const d = await tx.selectFrom("apple_mdm_devices").select(["id", "device_name", "serial"]).where("id", "=", id).executeTakeFirst();
        if (!d) throw notFound("Device");
        const u = user_id ? await tx.selectFrom("users").select("email").where("id", "=", user_id).executeTakeFirst() : null;
        if (user_id && !u) throw badRequest("unknown_user", "No such person");
        await tx.updateTable("apple_mdm_devices").set({ assigned_user_id: user_id }).where("id", "=", id).execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.device_assigned", target: { type: "apple_mdm_device", id, display: d.device_name || d.serial }, details: { to: u?.email ?? null } });
        return reconcileProfiles(tx, deps, p.orgId, [id]); // their groups' profiles
      });
      for (const m of touched) await wake(deps, p.orgId, m);
      return c.body(null, 204);
    },
  );
}

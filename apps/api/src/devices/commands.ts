import { createRoute, z } from "@hono/zod-openapi";
import { createPrivateKey, generateKeyPairSync, randomInt } from "node:crypto";
import { CompactSign } from "jose";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import { assertDeviceInScope, requirePermission, requireRecentMfa } from "../auth/guard.js";
import { ProviderError } from "../directory/sync/providers.js";
import { notifyRoles } from "../notify/send.js";
import type { Tx } from "../platform/db.js";
import { ApiError, badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { bearer, body, Id, iso, isoOrNull, json, problemResponses } from "../schemas.js";
import { mdmAction } from "./mdm-providers.js";
import { MDM_PROVIDER, mdmRowsForDevice } from "./mdm-signals.js";
import { ONLINE_WINDOW_MS } from "./service.js";

/**
 * Device actions (DEV-09): refresh, lock, restart and wipe.
 *
 * Through the agent, an action is a command the server signs with the
 * organization's Ed25519 key (CMD-03). The agent pinned that key at
 * enrollment and checks the signature, the device, the expiry and that it
 * hasn't run the command before, so neither a network attacker nor a forged
 * check-in response can make a device act. Through the MDM (Intune, Jamf),
 * the MDM does it: the only way to wipe, and the most reliable way to lock.
 */

export type Action = "refresh" | "lock" | "restart" | "wipe";
const TTL: Record<Action, number> = { refresh: 10 * 60_000, lock: 60 * 60_000, restart: 60 * 60_000, wipe: 0 };
export const CMD_TYP = "nexus-command+jwt";
const aad = (orgId: string) => `command_key:${orgId}`;

/** The organization's command-signing key, created on first use. */
export async function commandKey(tx: Tx, deps: Deps, orgId: string): Promise<{ publicKey: string; privatePem: string }> {
  const row = await tx.selectFrom("command_keys").selectAll().where("org_id", "=", orgId).executeTakeFirst();
  if (row) return { publicKey: row.public_key, privatePem: deps.sealer.open(row.private_key, aad(orgId)).toString() };
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = String(publicKey.export({ format: "jwk" }).x); // base64url, raw 32 bytes
  const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  await tx
    .insertInto("command_keys")
    .values({ org_id: orgId, public_key: pub, private_key: deps.sealer.seal(Buffer.from(pem), aad(orgId)) })
    .onConflict((oc) => oc.column("org_id").doNothing())
    .execute();
  return (await commandKey(tx, deps, orgId))!;
}

async function sign(privatePem: string, claims: Record<string, unknown>) {
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims))).setProtectedHeader({ alg: "EdDSA", typ: CMD_TYP }).sign(createPrivateKey(privatePem));
}

/** Commands waiting for this device, signed, for the check-in response. */
export async function pendingCommands(tx: Tx, deps: Deps, device: { id: string; org_id: string }) {
  await tx.updateTable("device_commands").set({ status: "expired", finished_at: new Date() }).where("device_id", "=", device.id).where("status", "in", ["queued", "sent"]).where("expires_at", "<", new Date()).execute();
  const rows = await tx.selectFrom("device_commands").select(["id", "action", "expires_at"]).where("device_id", "=", device.id).where("channel", "=", "agent").where("status", "in", ["queued", "sent"]).orderBy("created_at").limit(10).execute();
  if (!rows.length) return [];
  const key = await commandKey(tx, deps, device.org_id);
  const out = [];
  for (const r of rows) {
    out.push({ id: r.id, jws: await sign(key.privatePem, { jti: r.id, sub: device.id, act: r.action, iat: Math.floor(Date.now() / 1000), exp: Math.floor(r.expires_at.getTime() / 1000) }) });
  }
  await tx.updateTable("device_commands").set({ status: "sent", sent_at: new Date() }).where("id", "in", rows.map((r) => r.id)).where("status", "=", "queued").execute();
  return out;
}

export const CommandResults = z.array(z.object({ id: z.string().uuid(), status: z.enum(["done", "failed"]), output: z.string().max(4000).default("") })).max(20);

/** What the agent says happened. Only this device's own, still-open commands can be settled. */
export async function recordCommandResults(tx: Tx, device: { id: string; org_id: string; hostname: string }, results: z.infer<typeof CommandResults>, meta: { ip: string; userAgent: string; requestId: string }) {
  for (const r of results) {
    const row = await tx
      .updateTable("device_commands")
      .set({ status: r.status, output: r.output.slice(0, 2000), finished_at: new Date() })
      .where("id", "=", r.id)
      .where("device_id", "=", device.id)
      .where("status", "in", ["queued", "sent"])
      .returning(["action", "requested_by"])
      .executeTakeFirst();
    if (!row) continue;
    await audit(tx, device.org_id, { meta }, {
      type: "device.action_finished",
      actor: { type: "system", id: null, display: device.hostname },
      target: { type: "device", id: device.id, display: device.hostname },
      details: { command_id: r.id, action: row.action, status: r.status, output: r.output.slice(0, 500) },
    });
  }
}

const CommandOut = z
  .object({
    id: Id,
    action: z.enum(["refresh", "lock", "restart", "wipe"]),
    channel: z.enum(["agent", "mdm"]),
    status: z.enum(["queued", "sent", "done", "failed", "expired", "canceled"]),
    reason: z.string(),
    output: z.string(),
    requested_by: z.string().nullable(),
    created_at: z.string(),
    expires_at: z.string(),
    finished_at: z.string().nullable(),
  })
  .openapi("DeviceCommand");

async function history(tx: Tx, deviceId: string) {
  const rows = await tx
    .selectFrom("device_commands")
    .leftJoin("users", "users.id", "device_commands.requested_by")
    .selectAll("device_commands")
    .select("users.email")
    .where("device_commands.device_id", "=", deviceId)
    .orderBy("device_commands.created_at", "desc")
    .limit(50)
    .execute();
  return rows.map((r) => ({
    id: r.id,
    action: r.action,
    channel: r.channel,
    status: r.status,
    reason: r.reason,
    output: r.output,
    requested_by: r.email,
    created_at: iso(r.created_at),
    expires_at: iso(r.expires_at),
    finished_at: isoOrNull(r.finished_at),
  }));
}

const VERB: Record<Action, string> = { refresh: "refresh", lock: "lock", restart: "restart", wipe: "wipe" };

export function registerCommandRoutes(app: App) {
  const idParam = { params: z.object({ id: Id }) };

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/devices/{id}/actions",
      tags: ["Devices"],
      summary: "Refresh, lock, restart or wipe a device (lock, restart and wipe require recent MFA)",
      description:
        "refresh: the agent reports now. lock: through the MDM when the device is managed by one, else the agent. restart: the agent (in 1 minute), or the MDM if the device is offline. wipe: through the MDM only, irreversible: `confirm` must be the device's hostname. A Jamf lock returns the unlock PIN, once.",
      security: bearer,
      request: {
        ...idParam,
        ...body(
          z.object({
            action: z.enum(["refresh", "lock", "restart", "wipe"]),
            reason: z.string().trim().max(500).default(""),
            confirm: z.string().max(255).optional().openapi({ description: "For wipe: the device's hostname" }),
          }),
        ),
      },
      responses: { 202: json(z.object({ command: CommandOut, unlock_pin: z.string().nullable() }), "Requested"), ...problemResponses },
    }),
    async (c) => {
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      const perm = input.action === "wipe" ? "devices:wipe" : "devices:actions";
      const p = requirePermission(c, perm, { scoped: true }); // wipe is never scopable, so it stays org-wide
      const deps = c.get("deps");
      const meta = c.get("meta");
      if (input.action !== "refresh" && input.reason.length < 3) throw badRequest("reason_required", "Say why (it goes in the audit log and to the device's user)");

      // Decide the channel and gather what the MDM needs, before any network call.
      const plan = await deps.db.tenant(p.orgId, async (tx) => {
        await assertDeviceInScope(tx, p, perm, id);
        if (input.action !== "refresh") requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const d = await tx.selectFrom("devices").select(["id", "org_id", "hostname", "serial", "last_seen_at", "primary_user_id"]).where("id", "=", id).where("status", "=", "active").executeTakeFirst();
        if (!d) throw notFound("Device");
        if (input.action === "wipe" && input.confirm?.trim() !== d.hostname) throw badRequest("confirm_mismatch", `Type the device's name (${d.hostname}) to confirm the wipe`);
        const mdm = (await mdmRowsForDevice(tx, d)).find((r) => r.managed);
        const online = !!d.last_seen_at && Date.now() - d.last_seen_at.getTime() < ONLINE_WINDOW_MS;
        const channel: "agent" | "mdm" =
          input.action === "wipe" ? "mdm" : input.action === "lock" ? (mdm ? "mdm" : "agent") : input.action === "restart" ? (!online && mdm ? "mdm" : "agent") : "agent";
        if (channel === "mdm" && !mdm) throw conflict("no_mdm", `${d.hostname} isn't managed by a connected MDM, so it can't be wiped remotely. Connect Intune or Jamf in Device management.`);
        return { d, mdm, channel };
      });

      let status: "queued" | "done" | "failed" = "queued";
      let output = "";
      let pin: string | null = null;
      if (plan.channel === "mdm") {
        const m = plan.mdm!;
        if (m.provider === "jamf" && (input.action === "lock" || input.action === "wipe")) pin = String(randomInt(0, 1_000_000)).padStart(6, "0");
        try {
          await mdmAction(deps.cfg, m.provider, m.config, deps.sealer.open(m.secret, `mdm_connection:${m.connection_id}`).toString(), { external_id: m.external_id, management_id: m.management_id }, input.action as "lock" | "restart" | "wipe", pin);
          status = "done";
          output = `Sent to ${MDM_PROVIDER[m.provider]} (${m.connection})${pin ? "; unlock PIN shown to the requester" : ""}`;
        } catch (err) {
          status = "failed";
          output = err instanceof ProviderError ? err.message : `Unexpected error: ${(err as Error).message}`;
          pin = null;
        }
      }

      const command = await deps.db.tenant(p.orgId, async (tx) => {
        const cid = newId();
        await tx
          .insertInto("device_commands")
          .values({
            id: cid,
            org_id: p.orgId,
            device_id: id,
            action: input.action,
            channel: plan.channel,
            status,
            reason: input.reason,
            output,
            requested_by: p.userId,
            expires_at: new Date(Date.now() + (TTL[input.action] || 60_000)),
            ...(status !== "queued" ? { sent_at: new Date(), finished_at: new Date() } : {}),
          })
          .execute();
        await audit(tx, p.orgId, { principal: p, meta }, {
          type: "device.action_requested",
          outcome: status === "failed" ? "failure" : "success",
          target: { type: "device", id, display: plan.d.hostname },
          details: { command_id: cid, action: input.action, channel: plan.channel, reason: input.reason, ...(status === "failed" ? { error: output } : {}) },
        });
        if (input.action === "wipe" || input.action === "lock") {
          await notifyRoles(tx, p.orgId, ["owner", "admin", "security_analyst"], {
            category: "devices.action",
            severity: input.action === "wipe" ? "critical" : "warning",
            title: `${p.email} ${status === "failed" ? `tried to ${VERB[input.action]}` : `${VERB[input.action] === "wipe" ? "wiped" : "locked"}`} ${plan.d.hostname}`,
            body: input.reason,
            entity: { type: "device", id },
            link: `/devices/${id}`,
          });
        }
        return (await history(tx, id)).find((x) => x.id === cid)!;
      });
      if (status === "failed") throw new ApiError(502, "mdm_failed", output, { command });
      return c.json({ command, unlock_pin: pin }, 202);
    },
  );

  app.openapi(
    createRoute({ method: "get", path: "/v1/devices/{id}/commands", tags: ["Devices"], summary: "Actions taken on a device", security: bearer, request: idParam, responses: { 200: json(z.object({ data: z.array(CommandOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read", { scoped: true });
      const id = c.req.valid("param").id;
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, async (tx) => (await assertDeviceInScope(tx, p, "devices:read", id), history(tx, id))) }, 200);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/devices/{id}/commands/{command_id}/cancel",
      tags: ["Devices"],
      summary: "Cancel an action the device hasn't picked up yet",
      security: bearer,
      request: { params: z.object({ id: Id, command_id: Id }) },
      responses: { 200: json(z.object({ data: z.array(CommandOut) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:actions");
      const { id, command_id } = c.req.valid("param");
      const data = await c.get("deps").db.tenant(p.orgId, async (tx) => {
        const r = await tx.updateTable("device_commands").set({ status: "canceled", finished_at: new Date() }).where("id", "=", command_id).where("device_id", "=", id).where("status", "=", "queued").returning("action").executeTakeFirst();
        if (!r) throw conflict("not_cancelable", "Only actions the device hasn't picked up yet can be canceled");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "device.action_canceled", target: { type: "device", id }, details: { command_id, action: r.action } });
        return history(tx, id);
      });
      return c.json({ data }, 200);
    },
  );
}

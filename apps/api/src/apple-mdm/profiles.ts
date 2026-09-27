import { randomUUID } from "node:crypto";
import { createRoute, z } from "@hono/zod-openapi";
import plist from "plist";
import type { App, Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { requirePermission, requireRecentMfa } from "../auth/guard.js";
import { verifiedFactorTypes } from "../auth/routes.js";
import type { Tx } from "../platform/db.js";
import { badRequest, conflict, notFound } from "../platform/errors.js";
import { newId } from "../platform/ids.js";
import { isUniqueViolation } from "../platform/db.js";
import { bearer, body, Id, iso, json, problemResponses } from "../schemas.js";
import { queueCommand, wake } from "./service.js";

/**
 * Configuration profiles for Macs in Nexus MDM: upload a .mobileconfig (or build one from a
 * template), target it at every Mac or at groups (through the Mac's Nexus agent user), and Nexus
 * installs it where it's missing or changed and removes it where it's no longer wanted. Payloads
 * are sealed: profiles carry Wi-Fi passwords and the like. A profile that would enroll the Mac in
 * another MDM is refused.
 */

const aad = (id: string) => `apple_mdm_profile:${id}`;
type Target = { all?: boolean; group_ids?: string[] };
const TargetIn = z
  .union([z.object({ all: z.literal(true) }), z.object({ group_ids: z.array(Id).min(1).max(50) })])
  .default({ all: true })
  .openapi({ description: "Every enrolled Mac, or the Macs of people in these groups" });

const FORBIDDEN = new Set(["com.apple.mdm", "com.apple.dep.mdm"]);

/** Checks a .mobileconfig and reads its identifier and payload types. */
export function readProfile(xml: string) {
  let v: unknown;
  try {
    v = plist.parse(xml);
  } catch {
    throw badRequest("invalid_profile", "That isn't a configuration profile (an XML .mobileconfig). Signed profiles aren't supported yet: upload the unsigned one.");
  }
  const p = v as Record<string, unknown>;
  if (!p || typeof p !== "object" || p.PayloadType !== "Configuration" || typeof p.PayloadIdentifier !== "string" || !Array.isArray(p.PayloadContent)) {
    throw badRequest("invalid_profile", "A configuration profile needs PayloadType Configuration, a PayloadIdentifier and PayloadContent");
  }
  const types = (p.PayloadContent as Record<string, unknown>[]).map((c) => String(c?.PayloadType ?? ""));
  if (types.some((t) => FORBIDDEN.has(t))) throw badRequest("mdm_payload", "A profile can't enroll the Mac in another device management server");
  if (p.PayloadIdentifier.length > 200) throw badRequest("invalid_profile", "PayloadIdentifier is too long");
  return { identifier: p.PayloadIdentifier, types };
}

// ---- Templates --------------------------------------------------------------------------------

export const TEMPLATES = {
  screen_lock: {
    title: "Screen lock",
    settings: z.object({ idle_minutes: z.number().int().min(1).max(60).default(10) }),
    payload: (s: { idle_minutes: number }) => [{ PayloadType: "com.apple.screensaver", idleTime: s.idle_minutes * 60, askForPassword: true, askForPasswordDelay: 0 }],
  },
  firewall: {
    title: "Firewall",
    settings: z.object({ stealth: z.boolean().default(false), block_all_incoming: z.boolean().default(false) }),
    payload: (s: { stealth: boolean; block_all_incoming: boolean }) => [{ PayloadType: "com.apple.security.firewall", EnableFirewall: true, EnableStealthMode: s.stealth, BlockAllIncoming: s.block_all_incoming }],
  },
  wifi: {
    title: "Wi-Fi network",
    settings: z.object({ ssid: z.string().trim().min(1).max(32), password: z.string().min(8).max(63), hidden: z.boolean().default(false) }),
    payload: (s: { ssid: string; password: string; hidden: boolean }) => [{ PayloadType: "com.apple.wifi.managed", SSID_STR: s.ssid, HIDDEN_NETWORK: s.hidden, AutoJoin: true, EncryptionType: "WPA2", Password: s.password }],
  },
  software_update: {
    title: "Automatic macOS updates",
    settings: z.object({}),
    payload: () => [
      { PayloadType: "com.apple.SoftwareUpdate", AutomaticCheckEnabled: true, AutomaticDownload: true, AutomaticallyInstallMacOSUpdates: true, CriticalUpdateInstall: true, ConfigDataInstall: true, AutomaticallyInstallAppUpdates: true },
    ],
  },
  login_message: {
    title: "Login window message",
    settings: z.object({ message: z.string().trim().min(1).max(300) }),
    payload: (s: { message: string }) => [{ PayloadType: "com.apple.loginwindow", LoginwindowText: s.message }],
  },
} as const;
export type TemplateKind = keyof typeof TEMPLATES;

export function buildProfile(orgId: string, name: string, payloads: Record<string, unknown>[]) {
  const id = randomUUID().toUpperCase();
  const identifier = `com.votal.nexus.profile.${id.toLowerCase()}`;
  const xml = plist.build({
    PayloadType: "Configuration",
    PayloadVersion: 1,
    PayloadIdentifier: identifier,
    PayloadUUID: id,
    PayloadDisplayName: name,
    PayloadOrganization: "Votal Nexus",
    PayloadScope: "System",
    PayloadContent: payloads.map((p, i) => ({ PayloadVersion: 1, PayloadIdentifier: `${identifier}.${i}`, PayloadUUID: randomUUID().toUpperCase(), PayloadDisplayName: name, ...p })),
  } as plist.PlistValue);
  return { identifier, xml, orgId };
}

// ---- Reconciliation ---------------------------------------------------------------------------

async function macGroups(tx: Tx, mdmDeviceId: string) {
  const d = await tx.selectFrom("apple_mdm_devices").leftJoin("devices", "devices.id", "apple_mdm_devices.device_id").select(["devices.primary_user_id"]).where("apple_mdm_devices.id", "=", mdmDeviceId).executeTakeFirst();
  if (!d?.primary_user_id) return new Set<string>();
  return new Set((await tx.selectFrom("group_members").select("group_id").where("user_id", "=", d.primary_user_id).execute()).map((g) => g.group_id));
}
const wants = (t: Target, groups: Set<string>) => !!t.all || (t.group_ids ?? []).some((g) => groups.has(g));

/**
 * Makes the Macs' profiles match: installs what's missing or changed, removes what's no longer
 * wanted. Returns the Macs it queued commands for (to wake after commit).
 */
export async function reconcileProfiles(tx: Tx, deps: Pick<Deps, "sealer">, orgId: string, mdmDeviceIds?: string[]) {
  let q = tx.selectFrom("apple_mdm_devices").select("id").where("status", "=", "enrolled");
  if (mdmDeviceIds) q = mdmDeviceIds.length ? q.where("id", "in", mdmDeviceIds) : q.where("id", "=", "00000000-0000-0000-0000-000000000000");
  const macs = (await q.execute()).map((m) => m.id);
  if (!macs.length) return [];
  const profiles = await tx.selectFrom("apple_mdm_profiles").select(["id", "identifier", "target", "updated_at", "payload"]).execute();
  const touched = new Set<string>();
  for (const mac of macs) {
    const groups = await macGroups(tx, mac);
    const have = new Map((await tx.selectFrom("apple_mdm_device_profiles").selectAll().where("mdm_device_id", "=", mac).execute()).map((r) => [r.identifier, r]));
    const wanted = profiles.filter((p) => wants(p.target as Target, groups));
    for (const p of wanted) {
      const cur = have.get(p.identifier);
      const fresh = cur && (cur.status === "installed" || cur.status === "installing") && cur.installed_version?.getTime() === p.updated_at.getTime();
      if (fresh) continue;
      const xml = deps.sealer.open(p.payload, aad(p.id));
      const cid = await queueCommand(tx, orgId, mac, "InstallProfile", { Payload: { $data: xml.toString("base64") } }, { userId: null, reason: "Configuration profile" });
      await tx
        .insertInto("apple_mdm_device_profiles")
        .values({ org_id: orgId, mdm_device_id: mac, identifier: p.identifier, profile_id: p.id, status: "installing", command_id: cid, installed_version: p.updated_at, updated_at: new Date() })
        .onConflict((oc) => oc.columns(["mdm_device_id", "identifier"]).doUpdateSet({ profile_id: p.id, status: "installing", detail: "", command_id: cid, installed_version: p.updated_at, updated_at: new Date() }))
        .execute();
      touched.add(mac);
    }
    const wantedIds = new Set(wanted.map((p) => p.identifier));
    for (const [identifier, row] of have) {
      if (wantedIds.has(identifier) || row.status === "removing") continue;
      if (row.status === "failed") {
        await tx.deleteFrom("apple_mdm_device_profiles").where("mdm_device_id", "=", mac).where("identifier", "=", identifier).execute();
        continue;
      }
      const cid = await queueCommand(tx, orgId, mac, "RemoveProfile", { Identifier: identifier }, { userId: null, reason: "Configuration profile removed" });
      await tx.updateTable("apple_mdm_device_profiles").set({ status: "removing", command_id: cid, updated_at: new Date() }).where("mdm_device_id", "=", mac).where("identifier", "=", identifier).execute();
      touched.add(mac);
    }
  }
  return [...touched];
}

/** The Mac answered an InstallProfile / RemoveProfile. */
export async function profileResult(tx: Tx, commandId: string, ok: boolean, error: string) {
  const row = await tx.selectFrom("apple_mdm_device_profiles").select(["mdm_device_id", "identifier", "status"]).where("command_id", "=", commandId).executeTakeFirst();
  if (!row) return;
  if (row.status === "removing" && ok) {
    await tx.deleteFrom("apple_mdm_device_profiles").where("mdm_device_id", "=", row.mdm_device_id).where("identifier", "=", row.identifier).execute();
    return;
  }
  await tx
    .updateTable("apple_mdm_device_profiles")
    .set({ status: ok ? "installed" : "failed", detail: ok ? "" : error.slice(0, 500), updated_at: new Date() })
    .where("mdm_device_id", "=", row.mdm_device_id)
    .where("identifier", "=", row.identifier)
    .execute();
}

// ---- Routes -------------------------------------------------------------------------------------

const ProfileOut = z
  .object({
    id: Id,
    name: z.string(),
    identifier: z.string(),
    payload_types: z.array(z.string()),
    source: z.enum(["upload", "template"]),
    target: z.object({ all: z.boolean().optional(), group_ids: z.array(Id).optional() }),
    counts: z.object({ installed: z.number().int(), installing: z.number().int(), failed: z.number().int() }),
    updated_at: z.string(),
  })
  .openapi("AppleMdmProfile");

async function listProfiles(tx: Tx, ids?: string[]) {
  let q = tx.selectFrom("apple_mdm_profiles").select(["id", "name", "identifier", "payload_types", "source", "target", "updated_at"]).orderBy("name");
  if (ids) q = q.where("id", "in", ids);
  const rows = await q.execute();
  const states = await tx.selectFrom("apple_mdm_device_profiles").select(["profile_id", "status"]).execute();
  return rows.map((r) => {
    const mine = states.filter((s) => s.profile_id === r.id);
    const n = (st: string) => mine.filter((s) => s.status === st).length;
    return { ...r, target: r.target as Target, counts: { installed: n("installed"), installing: n("installing"), failed: n("failed") }, updated_at: iso(r.updated_at) };
  });
}

async function wakeAll(deps: Deps, orgId: string, macs: string[]) {
  for (const m of macs) await wake(deps, orgId, m);
}

export function registerAppleMdmProfileRoutes(app: App) {
  app.openapi(
    createRoute({ method: "get", path: "/v1/apple-mdm/profiles", tags: ["Apple MDM"], summary: "Configuration profiles and where they're installed", security: bearer, responses: { 200: json(z.object({ data: z.array(ProfileOut) })), ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      return c.json({ data: await c.get("deps").db.tenant(p.orgId, (tx) => listProfiles(tx)) }, 200);
    },
  );

  const save = async (c: any, input: { name: string; xml: string; source: "upload" | "template"; target: Target; identifier?: string; types: string[] }) => {
    const p = requirePermission(c, "devices:enforce");
    const deps: Deps = c.get("deps");
    let macs: string[] = [];
    const out = await deps.db.tenant(p.orgId, async (tx) => {
      requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
      const id = newId();
      try {
        await tx
          .insertInto("apple_mdm_profiles")
          .values({ id, org_id: p.orgId, name: input.name, identifier: input.identifier!, payload: deps.sealer.seal(Buffer.from(input.xml), aad(id)), payload_types: input.types, source: input.source, target: JSON.stringify(input.target), created_by: p.userId })
          .execute();
      } catch (e) {
        if (isUniqueViolation(e)) throw conflict("duplicate_profile", `A profile with identifier ${input.identifier} already exists`);
        throw e;
      }
      await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.profile_saved", target: { type: "apple_mdm_profile", id, display: input.name }, details: { identifier: input.identifier, payload_types: input.types, target: input.target, source: input.source } });
      macs = await reconcileProfiles(tx, deps, p.orgId);
      return (await listProfiles(tx, [id]))[0]!;
    });
    await wakeAll(deps, p.orgId, macs);
    return out;
  };

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apple-mdm/profiles",
      tags: ["Apple MDM"],
      summary: "Upload a configuration profile (.mobileconfig)",
      description: "Installed on the targeted Macs right away (they're woken through APNs). Needs `devices:enforce` and a recent MFA.",
      security: bearer,
      request: body(z.object({ name: z.string().trim().min(1).max(100), mobileconfig: z.string().min(50).max(1_000_000), target: TargetIn })),
      responses: { 201: json(ProfileOut), ...problemResponses },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const { identifier, types } = readProfile(input.mobileconfig);
      return c.json(await save(c, { name: input.name, xml: input.mobileconfig, source: "upload", target: input.target, identifier, types }), 201);
    },
  );

  app.openapi(
    createRoute({
      method: "post",
      path: "/v1/apple-mdm/profiles/template",
      tags: ["Apple MDM"],
      summary: "Build a configuration profile from a template",
      description: "Templates: screen_lock {idle_minutes}, firewall {stealth, block_all_incoming}, wifi {ssid, password, hidden}, software_update {}, login_message {message}.",
      security: bearer,
      request: body(z.object({ name: z.string().trim().min(1).max(100), kind: z.enum(Object.keys(TEMPLATES) as [TemplateKind, ...TemplateKind[]]), settings: z.record(z.string(), z.unknown()).default({}), target: TargetIn })),
      responses: { 201: json(ProfileOut), ...problemResponses },
    }),
    async (c) => {
      const input = c.req.valid("json");
      const t = TEMPLATES[input.kind];
      const parsed = t.settings.safeParse(input.settings);
      if (!parsed.success) throw badRequest("invalid_settings", parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
      const payloads = (t.payload as (s: unknown) => Record<string, unknown>[])(parsed.data);
      const built = buildProfile("", input.name, payloads);
      return c.json(await save(c, { name: input.name, xml: built.xml, source: "template", target: input.target, identifier: built.identifier, types: payloads.map((x) => String(x.PayloadType)) }), 201);
    },
  );

  app.openapi(
    createRoute({
      method: "patch",
      path: "/v1/apple-mdm/profiles/{id}",
      tags: ["Apple MDM"],
      summary: "Change who gets a profile, or replace its contents",
      security: bearer,
      request: { params: z.object({ id: Id }), ...body(z.object({ name: z.string().trim().min(1).max(100).optional(), target: TargetIn.optional(), mobileconfig: z.string().min(50).max(1_000_000).optional() })) },
      responses: { 200: json(ProfileOut), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      const input = c.req.valid("json");
      let macs: string[] = [];
      const out = await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const cur = await tx.selectFrom("apple_mdm_profiles").select(["identifier", "name"]).where("id", "=", id).executeTakeFirst();
        if (!cur) throw notFound("Profile");
        let content = {};
        if (input.mobileconfig) {
          const r = readProfile(input.mobileconfig);
          if (r.identifier !== cur.identifier) throw badRequest("identifier_changed", `The new profile must keep the identifier ${cur.identifier} (a different one is a different profile)`);
          content = { payload: deps.sealer.seal(Buffer.from(input.mobileconfig), aad(id)), payload_types: r.types };
        }
        await tx
          .updateTable("apple_mdm_profiles")
          .set({ ...(input.name ? { name: input.name } : {}), ...(input.target ? { target: JSON.stringify(input.target) } : {}), ...content, updated_at: new Date() })
          .where("id", "=", id)
          .execute();
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.profile_saved", target: { type: "apple_mdm_profile", id, display: input.name ?? cur.name }, details: { target: input.target, content_replaced: !!input.mobileconfig } });
        macs = await reconcileProfiles(tx, deps, p.orgId);
        return (await listProfiles(tx, [id]))[0]!;
      });
      await wakeAll(deps, p.orgId, macs);
      return c.json(out, 200);
    },
  );

  app.openapi(
    createRoute({ method: "delete", path: "/v1/apple-mdm/profiles/{id}", tags: ["Apple MDM"], summary: "Delete a profile (it's removed from the Macs that have it)", security: bearer, request: { params: z.object({ id: Id }) }, responses: { 204: { description: "Deleted" }, ...problemResponses } }),
    async (c) => {
      const p = requirePermission(c, "devices:enforce");
      const deps = c.get("deps");
      const { id } = c.req.valid("param");
      let macs: string[] = [];
      await deps.db.tenant(p.orgId, async (tx) => {
        requireRecentMfa(c, p, (await verifiedFactorTypes(tx, p.userId)).length > 0);
        const r = await tx.deleteFrom("apple_mdm_profiles").where("id", "=", id).returning(["name", "identifier"]).executeTakeFirst();
        if (!r) throw notFound("Profile");
        await audit(tx, p.orgId, { principal: p, meta: c.get("meta") }, { type: "apple_mdm.profile_deleted", target: { type: "apple_mdm_profile", id, display: r.name }, details: { identifier: r.identifier } });
        macs = await reconcileProfiles(tx, deps, p.orgId);
      });
      await wakeAll(deps, p.orgId, macs);
      return c.body(null, 204);
    },
  );

  app.openapi(
    createRoute({
      method: "get",
      path: "/v1/apple-mdm/devices/{id}/profiles",
      tags: ["Apple MDM"],
      summary: "A Mac's configuration profiles",
      security: bearer,
      request: { params: z.object({ id: Id }) },
      responses: { 200: json(z.object({ data: z.array(z.object({ identifier: z.string(), name: z.string().nullable(), status: z.string(), detail: z.string(), updated_at: z.string() })) })), ...problemResponses },
    }),
    async (c) => {
      const p = requirePermission(c, "devices:read");
      const { id } = c.req.valid("param");
      const rows = await c.get("deps").db.tenant(p.orgId, (tx) =>
        tx
          .selectFrom("apple_mdm_device_profiles")
          .leftJoin("apple_mdm_profiles", "apple_mdm_profiles.id", "apple_mdm_device_profiles.profile_id")
          .select(["apple_mdm_device_profiles.identifier", "apple_mdm_profiles.name", "apple_mdm_device_profiles.status", "apple_mdm_device_profiles.detail", "apple_mdm_device_profiles.updated_at"])
          .where("apple_mdm_device_profiles.mdm_device_id", "=", id)
          .execute(),
      );
      return c.json({ data: rows.map((r) => ({ ...r, name: r.name ?? null, updated_at: iso(r.updated_at) })) }, 200);
    },
  );
}

import { randomInt, randomUUID } from "node:crypto";
import plist from "plist";
import type { Deps } from "../context.js";
import type { Tx } from "../platform/db.js";
import { pushKeyAad } from "./pki.js";
import { pushMdm } from "./push.js";

/** What admins can send, and the command dictionary Apple expects for each. */
const MAC = ["macos"] as const;
const MOBILE = ["ios", "ipados"] as const;
const ALL = ["macos", "ios", "ipados"] as const;

/**
 * Commands admins can send, with who may send them and which devices take them. Mobile-only ones
 * (Lost Mode, clearing a passcode) and Mac-only ones (a lock PIN) follow Apple's MDM reference;
 * restarting, shutting down and updating an iPhone or iPad need it to be supervised.
 */
export const COMMANDS = {
  DeviceInformation: {
    perm: "devices:read",
    platforms: ALL,
    build: () => ({ Queries: ["DeviceName", "OSVersion", "BuildVersion", "ModelName", "Model", "ProductName", "SerialNumber", "DeviceCapacity", "AvailableDeviceCapacity", "IsSupervised", "IsActivationLockEnabled"] }),
  },
  SecurityInfo: { perm: "devices:read", platforms: ALL, build: () => ({}) },
  InstalledApplicationList: { perm: "devices:read", platforms: ALL, build: () => ({}) },
  ProfileList: { perm: "devices:read", platforms: ALL, build: () => ({}) },
  DeviceLock: { perm: "devices:actions", platforms: ALL, build: (o: { pin: string; message?: string; phone?: string }) => ({ ...(o.pin ? { PIN: o.pin } : {}), ...(o.message ? { Message: o.message } : {}), ...(o.phone ? { PhoneNumber: o.phone } : {}) }) },
  RestartDevice: { perm: "devices:actions", platforms: ALL, build: () => ({}) },
  ShutDownDevice: { perm: "devices:actions", platforms: ALL, build: () => ({}) },
  // Without Updates, the device installs everything available with the default action.
  ScheduleOSUpdate: { perm: "devices:updates", platforms: ALL, build: () => ({}) },
  EraseDevice: { perm: "devices:wipe", platforms: ALL, build: (o: { pin: string }) => (o.pin ? { PIN: o.pin } : {}) },
  // iPhone and iPad: a forgotten passcode, and lost devices (Lost Mode needs supervision).
  ClearPasscode: { perm: "devices:actions", platforms: MOBILE, build: (o: { unlockToken?: string }) => ({ UnlockToken: { $data: o.unlockToken ?? "" } }) },
  EnableLostMode: { perm: "devices:actions", platforms: MOBILE, build: (o: { message?: string; phone?: string }) => ({ Message: o.message || "This device is lost. Please call the number shown.", ...(o.phone ? { PhoneNumber: o.phone } : {}) }) },
  PlayLostModeSound: { perm: "devices:actions", platforms: MOBILE, build: () => ({}) },
  DeviceLocation: { perm: "devices:actions", platforms: MOBILE, build: () => ({}) },
  DisableLostMode: { perm: "devices:actions", platforms: MOBILE, build: () => ({}) },
} as const;
export type RequestType = keyof typeof COMMANDS;
export const REQUEST_TYPES = Object.keys(COMMANDS) as RequestType[];
/** Macs take a 6-digit PIN with lock and erase (asked for at the Mac); iPhones and iPads don't. */
export const needsPin = (t: RequestType, platform = "macos") => platform === "macos" && (t === "DeviceLock" || t === "EraseDevice");

/** iPhone, iPad or Mac, from what the device reports (ProductName like "iPhone15,2", "iPad13,1", "Mac14,7"). */
export function platformOf(productName: string, model = ""): "macos" | "ios" | "ipados" | "other" {
  const p = `${productName} ${model}`;
  if (/\biP(hone|od)/.test(p)) return "ios";
  if (/\biPad/.test(p)) return "ipados";
  if (/\b(Mac|iMac|MacBook)/.test(p)) return "macos";
  return productName || model ? "other" : "macos";
}
export const newPin = () => String(randomInt(0, 1_000_000)).padStart(6, "0");

export async function queueCommand(tx: Tx, orgId: string, mdmDeviceId: string, type: RequestType | "InstallProfile" | "RemoveProfile", fields: Record<string, unknown>, who: { userId: string | null; reason: string }) {
  const id = randomUUID().toUpperCase();
  await tx
    .insertInto("apple_mdm_commands")
    .values({ id, org_id: orgId, mdm_device_id: mdmDeviceId, request_type: type, command: JSON.stringify({ RequestType: type, ...fields }), reason: who.reason, requested_by: who.userId })
    .execute();
  return id;
}

/** Asks APNs to wake the device (after the command is committed). Best effort: the device also checks in on its own. */
export async function wake(deps: Deps, orgId: string, mdmDeviceId: string): Promise<string | null> {
  const r = await deps.db.tenant(orgId, async (tx) => {
    const s = await tx.selectFrom("apple_mdm_settings").select(["push_cert", "push_key", "push_topic"]).where("org_id", "=", orgId).executeTakeFirst();
    const d = await tx.selectFrom("apple_mdm_devices").select(["push_token", "push_magic", "topic"]).where("id", "=", mdmDeviceId).executeTakeFirst();
    return { s, d };
  });
  if (!r.s?.push_cert || !r.s.push_key || !r.d?.push_token || !r.d.push_magic) return "no push certificate or token yet";
  try {
    const res = await pushMdm({ url: deps.cfg.appleMdmPushUrl, certPem: r.s.push_cert, keyPem: deps.sealer.open(r.s.push_key, pushKeyAad(orgId)).toString(), topic: r.d.topic || r.s.push_topic!, token: r.d.push_token, pushMagic: r.d.push_magic });
    return res.ok ? null : `APNs refused the push (${res.status}${res.reason ? `: ${res.reason}` : ""})`;
  } catch (e) {
    return `APNs: ${(e as Error).message}`;
  }
}

/** The enrollment profile: the device's identity (PKCS#12) and the MDM payload that uses it. */
export function enrollmentProfile(o: { orgName: string; orgId: string; apiUrl: string; topic: string; p12: Buffer; p12Password: string }) {
  const identityUuid = randomUUID().toUpperCase();
  const profile = {
    PayloadType: "Configuration",
    PayloadVersion: 1,
    PayloadIdentifier: `com.votal.nexus.mdm.${o.orgId}`,
    PayloadUUID: randomUUID().toUpperCase(),
    PayloadDisplayName: `${o.orgName} device management`,
    PayloadDescription: `Lets ${o.orgName} manage this Mac with Votal Nexus.`,
    PayloadOrganization: o.orgName,
    PayloadScope: "System",
    PayloadRemovalDisallowed: false,
    PayloadContent: [
      {
        PayloadType: "com.apple.security.pkcs12",
        PayloadVersion: 1,
        PayloadIdentifier: `com.votal.nexus.mdm.${o.orgId}.identity`,
        PayloadUUID: identityUuid,
        PayloadDisplayName: "Device identity",
        PayloadContent: o.p12,
        Password: o.p12Password,
      },
      {
        PayloadType: "com.apple.mdm",
        PayloadVersion: 1,
        PayloadIdentifier: `com.votal.nexus.mdm.${o.orgId}.mdm`,
        PayloadUUID: randomUUID().toUpperCase(),
        PayloadDisplayName: "Device management",
        ServerURL: `${o.apiUrl}/mdm/apple/connect`,
        CheckInURL: `${o.apiUrl}/mdm/apple/checkin`,
        Topic: o.topic,
        IdentityCertificateUUID: identityUuid,
        SignMessage: true,
        CheckOutWhenRemoved: true,
        AccessRights: 8191,
        ServerCapabilities: ["com.apple.mdm.bootstraptoken"],
      },
    ],
  };
  return Buffer.from(plist.build(profile as unknown as plist.PlistValue));
}

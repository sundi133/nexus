import { randomInt, randomUUID } from "node:crypto";
import plist from "plist";
import type { Deps } from "../context.js";
import type { Tx } from "../platform/db.js";
import { pushKeyAad } from "./pki.js";
import { pushMdm } from "./push.js";

/** What admins can send, and the command dictionary Apple expects for each. */
export const COMMANDS = {
  DeviceInformation: {
    perm: "devices:read",
    build: () => ({ Queries: ["DeviceName", "OSVersion", "BuildVersion", "ModelName", "Model", "ProductName", "SerialNumber", "DeviceCapacity", "AvailableDeviceCapacity", "IsSupervised", "IsActivationLockEnabled"] }),
  },
  SecurityInfo: { perm: "devices:read", build: () => ({}) },
  InstalledApplicationList: { perm: "devices:read", build: () => ({}) },
  ProfileList: { perm: "devices:read", build: () => ({}) },
  DeviceLock: { perm: "devices:actions", build: (o: { pin: string; message?: string }) => ({ PIN: o.pin, ...(o.message ? { Message: o.message } : {}) }) },
  RestartDevice: { perm: "devices:actions", build: () => ({}) },
  ShutDownDevice: { perm: "devices:actions", build: () => ({}) },
  // Without Updates, macOS installs everything available with the default action.
  ScheduleOSUpdate: { perm: "devices:updates", build: () => ({}) },
  EraseDevice: { perm: "devices:wipe", build: (o: { pin: string }) => ({ PIN: o.pin }) },
} as const;
export type RequestType = keyof typeof COMMANDS;
export const REQUEST_TYPES = Object.keys(COMMANDS) as RequestType[];
export const needsPin = (t: RequestType) => t === "DeviceLock" || t === "EraseDevice";
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

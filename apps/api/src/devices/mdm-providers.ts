import { z } from "@hono/zod-openapi";
import type { Config } from "../config.js";
import { entraToken, getJson, graphPages, ProviderError } from "../directory/sync/providers.js";
import { assertSafeUrl } from "../platform/outbound.js";

/**
 * Read-only clients for MDMs (device signals). Each returns the devices the
 * MDM manages, normalised; matching to Nexus devices happens by serial number.
 *
 * - Microsoft Intune: Graph managedDevices (application permission
 *   DeviceManagementManagedDevices.Read.All), with its compliance state.
 * - Jamf Pro: the Jamf Pro API with an API client (role with "Read Computers");
 *   Jamf has no single compliance verdict, so a managed Mac counts as compliant
 *   unless its FileVault state says otherwise.
 */

export type MdmDevice = {
  external_id: string;
  serial: string;
  name: string;
  platform: string;
  os_version: string;
  user_email: string;
  managed: boolean;
  compliant: boolean | null;
  compliance_detail: string;
  encrypted: boolean | null;
  last_contact_at: Date | null;
};

export const IntuneConfig = z.object({
  tenant_id: z.string().regex(/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[A-Za-z0-9.-]+\.[A-Za-z]{2,})$/i, "A tenant ID (GUID) or primary domain"),
  client_id: z.uuid(),
});
export const JamfConfig = z.object({
  base_url: z.string().url().max(300).openapi({ example: "https://acme.jamfcloud.com" }),
  client_id: z.string().min(1).max(200),
});

type Endpoints = Config;

const date = (v: unknown) => {
  const d = typeof v === "string" && v ? new Date(v) : null;
  return d && !Number.isNaN(d.getTime()) && d.getFullYear() > 2000 ? d : null;
};

const INTUNE_STATE: Record<string, { compliant: boolean | null; detail: string }> = {
  compliant: { compliant: true, detail: "" },
  ingraceperiod: { compliant: true, detail: "in Intune's grace period" },
  noncompliant: { compliant: false, detail: "" },
  conflict: { compliant: false, detail: "conflicting policies" },
  error: { compliant: false, detail: "policy error" },
  unknown: { compliant: null, detail: "" },
  configmanager: { compliant: null, detail: "managed by Configuration Manager" },
};

export async function fetchIntune(ep: Endpoints, rawCfg: unknown, secret: string): Promise<MdmDevice[]> {
  const cfg = IntuneConfig.parse(rawCfg);
  const token = await entraToken(ep, cfg, secret);
  const select = "id,deviceName,serialNumber,operatingSystem,osVersion,complianceState,isEncrypted,userPrincipalName,emailAddress,lastSyncDateTime,managementState";
  const rows = await graphPages(ep, `${ep.graphBase}/v1.0/deviceManagement/managedDevices?$select=${select}&$top=999`, token, "Listing Intune devices");
  return rows.map((x) => {
    const state = INTUNE_STATE[String(x.complianceState ?? "unknown").toLowerCase()] ?? { compliant: null, detail: String(x.complianceState ?? "") };
    const os = String(x.operatingSystem ?? "").toLowerCase();
    return {
      external_id: String(x.id),
      serial: String(x.serialNumber ?? "").trim(),
      name: String(x.deviceName ?? "").slice(0, 200),
      platform: os.includes("windows") ? "windows" : os.includes("mac") ? "macos" : os.includes("linux") ? "linux" : os,
      os_version: String(x.osVersion ?? ""),
      user_email: String(x.userPrincipalName || x.emailAddress || "").toLowerCase(),
      managed: String(x.managementState ?? "managed").toLowerCase() !== "retirepending" && String(x.managementState ?? "managed").toLowerCase() !== "wipepending",
      compliant: state.compliant,
      compliance_detail: state.detail,
      encrypted: typeof x.isEncrypted === "boolean" ? x.isEncrypted : null,
      last_contact_at: date(x.lastSyncDateTime),
    };
  });
}

async function jamfToken(base: string, cfg: z.infer<typeof JamfConfig>, secret: string) {
  const body = await getJson(
    `${base}/api/oauth/token`,
    { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "client_credentials", client_id: cfg.client_id, client_secret: secret }) },
    "Jamf sign-in",
  );
  if (!body?.access_token) throw new ProviderError("Jamf returned no access token", true);
  return String(body.access_token);
}

export async function fetchJamf(ep: Endpoints, rawCfg: unknown, secret: string): Promise<MdmDevice[]> {
  const cfg = JamfConfig.parse(rawCfg);
  const base = cfg.base_url.replace(/\/+$/, "");
  await assertSafeUrl(base, { allowPrivate: ep.allowPrivateOutbound });
  const token = await jamfToken(base, cfg, secret);
  const out: MdmDevice[] = [];
  const size = 200;
  for (let page = 0; page < 500; page++) {
    const q = new URLSearchParams({ page: String(page), "page-size": String(size), sort: "id:asc" });
    for (const s of ["GENERAL", "HARDWARE", "OPERATING_SYSTEM", "DISK_ENCRYPTION", "USER_AND_LOCATION"]) q.append("section", s);
    const body = await getJson(`${base}/api/v1/computers-inventory?${q}`, { headers: { authorization: `Bearer ${token}`, accept: "application/json" } }, "Listing Jamf computers");
    const results: any[] = body?.results ?? [];
    for (const x of results) {
      const managed = x.general?.remoteManagement?.managed !== false;
      const fv = String(x.diskEncryption?.fileVault2Status ?? x.diskEncryption?.bootPartitionEncryptionDetails?.partitionFileVault2State ?? "").toUpperCase();
      const encrypted = fv ? fv === "ALL_ENCRYPTED" || fv === "BOOT_ENCRYPTED" || fv === "ENCRYPTED" : null;
      out.push({
        external_id: String(x.id),
        serial: String(x.hardware?.serialNumber ?? "").trim(),
        name: String(x.general?.name ?? "").slice(0, 200),
        platform: "macos",
        os_version: String(x.operatingSystem?.version ?? ""),
        user_email: String(x.userAndLocation?.email ?? "").toLowerCase(),
        managed,
        compliant: !managed ? false : encrypted === false ? false : null,
        compliance_detail: encrypted === false ? "FileVault is off" : "",
        encrypted,
        last_contact_at: date(x.general?.lastContactTime),
      });
    }
    if (results.length < size || out.length >= Number(body?.totalCount ?? Infinity)) break;
  }
  return out;
}

export function fetchMdm(ep: Endpoints, provider: "intune" | "jamf", cfg: unknown, secret: string) {
  return provider === "intune" ? fetchIntune(ep, cfg, secret) : fetchJamf(ep, cfg, secret);
}

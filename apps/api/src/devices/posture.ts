import { z } from "@hono/zod-openapi";
import type { CheckStatus, Compliance, DevicePlatform } from "../platform/db-types.js";
import { usableSerial } from "./serial.js";
import { type AIContext, type AIInventory, classify, serverTarget } from "./ai.js";

/**
 * Device posture (SPEC DEV-05, DPOL-01/03). The agent reports raw facts; the
 * server alone decides compliance, so a tampered agent can't mark itself
 * compliant by changing a verdict, only by lying about facts (which signed
 * check-ins and future attestation make detectable).
 */

const OnOff = z.enum(["on", "off", "unknown"]);

export const PostureFacts = z
  .object({
    disk_encryption: z.object({ status: OnOff, detail: z.string().max(500).optional() }),
    firewall: z.object({ status: OnOff, detail: z.string().max(500).optional() }),
    screen_lock: z.object({ status: OnOff, delay_seconds: z.number().int().min(0).max(86_400).nullable().optional(), detail: z.string().max(500).optional() }),
    system_integrity: z.object({ status: OnOff, detail: z.string().max(500).optional() }),
  })
  .openapi("PostureFacts");
export type PostureFacts = z.infer<typeof PostureFacts>;

export const CHECK_KEYS = ["disk_encryption", "firewall", "screen_lock", "os_version", "system_integrity", "mdm_compliant", "ai_mcp_governed"] as const;
export type CheckKey = (typeof CHECK_KEYS)[number];

export const PolicyParams = {
  disk_encryption: z.object({}),
  firewall: z.object({}),
  screen_lock: z.object({ max_delay_minutes: z.number().int().min(0).max(60) }),
  os_version: z.object({ minimum: z.object({ macos: z.string().max(20), windows: z.string().max(30), linux: z.string().max(20) }) }),
  system_integrity: z.object({}),
  mdm_compliant: z.object({}),
  ai_mcp_governed: z.object({
    allowed_hosts: z
      .array(z.string().trim().toLowerCase().regex(/^(\*\.)?[a-z0-9.-]+$/, "A host name, or *.domain for its subdomains").max(200))
      .max(100)
      .openapi({ description: "Remote MCP hosts people may use directly, besides the Nexus gateway" }),
    allow_local: z.boolean().openapi({ description: "Allow MCP servers that run on the device (stdio)" }),
    allow_inline_secrets: z.boolean().openapi({ description: "Allow API keys and tokens written into MCP config files" }),
  }),
} as const;

export type PolicyMode = "audit" | "enforce";
export type Policy = { key: CheckKey; enabled: boolean; params: Record<string, unknown>; mode: PolicyMode; grace_hours: number };

const base = { enabled: true, mode: "enforce" as const, grace_hours: 0 };
export const DEFAULT_POLICIES: Policy[] = [
  { key: "disk_encryption", ...base, params: {} },
  { key: "firewall", ...base, params: {} },
  { key: "screen_lock", ...base, params: { max_delay_minutes: 10 } },
  // Empty minimum = not enforced for that platform until an admin sets one.
  { key: "os_version", ...base, params: { minimum: { macos: "14.0", windows: "10.0.19045", linux: "" } } },
  { key: "system_integrity", ...base, params: {} },
  // Off until an MDM is connected and an admin opts in.
  { key: "mdm_compliant", ...base, enabled: false, params: {} },
  // Off until an admin opts in; starts in audit mode so it reports without blocking anyone.
  { key: "ai_mcp_governed", ...base, enabled: false, mode: "audit", params: { allowed_hosts: [], allow_local: true, allow_inline_secrets: false } },
];

export const CHECK_INFO: Record<CheckKey, { title: string; why: string }> = {
  disk_encryption: { title: "Disk encryption", why: "A lost or stolen laptop must not expose company data." },
  firewall: { title: "Firewall", why: "Blocks unsolicited network connections to the device." },
  screen_lock: { title: "Screen lock", why: "An unattended, unlocked device is an open door." },
  os_version: { title: "Operating system up to date", why: "Old versions miss security fixes that attackers actively use." },
  system_integrity: { title: "System integrity protection", why: "SIP / Secure Boot stop malware from tampering with the OS." },
  mdm_compliant: { title: "Managed and compliant in your MDM", why: "Your MDM (Intune, Jamf) enforces settings Nexus doesn't check itself, like app control and configuration profiles." },
  ai_mcp_governed: {
    title: "AI tools use approved MCP servers",
    why: "MCP servers let AI assistants act with your access. Going through the Nexus gateway puts every tool call under policy and in the audit log, and keeps tokens out of config files.",
  },
};

const FIX: Record<CheckKey, Record<DevicePlatform, string>> = {
  disk_encryption: {
    macos: "Open System Settings → Privacy & Security → FileVault and turn it on.",
    windows: "Open Settings → Privacy & security → Device encryption (or BitLocker) and turn it on for the system drive.",
    linux: "Disk encryption (LUKS) is set up at install time. Ask IT to help re-provision this device.",
  },
  firewall: {
    macos: "Open System Settings → Network → Firewall and turn it on.",
    windows: "Open Windows Security → Firewall & network protection and turn on the firewall for all networks.",
    linux: "Enable the firewall, e.g. `sudo ufw enable` (Ubuntu) or `sudo systemctl enable --now firewalld`.",
  },
  screen_lock: {
    macos: "Open System Settings → Lock Screen and set “Require password after screen saver begins or display is turned off” to a short delay.",
    windows: "Open Settings → Accounts → Sign-in options and require sign-in when the PC wakes; set the screen to turn off after a few minutes.",
    linux: "In your desktop settings (Privacy → Screen Lock), turn on automatic screen lock with a short delay.",
  },
  os_version: {
    macos: "Open System Settings → General → Software Update and install the latest update.",
    windows: "Open Settings → Windows Update and install all available updates.",
    linux: "Install the latest updates with your package manager, then reboot.",
  },
  mdm_compliant: {
    macos: "Enroll this Mac in your organization's device management (for example Jamf or Intune), or fix what it reports. Ask IT if you're not sure how.",
    windows: "Enroll this PC in your organization's device management (Intune): Settings → Accounts → Access work or school. Then fix what Company Portal reports.",
    linux: "Linux devices are usually not managed by an MDM. Ask IT whether this policy applies to you.",
  },
  ai_mcp_governed: {
    macos: "Connect your AI tools (Claude, Cursor, VS Code…) to MCP servers through the Nexus MCP gateway (IT can give you the URL), and remove API keys written into MCP config files.",
    windows: "Connect your AI tools (Claude, Cursor, VS Code…) to MCP servers through the Nexus MCP gateway (IT can give you the URL), and remove API keys written into MCP config files.",
    linux: "Connect your AI tools (Claude, Cursor, VS Code…) to MCP servers through the Nexus MCP gateway (IT can give you the URL), and remove API keys written into MCP config files.",
  },
  system_integrity: {
    macos: "System Integrity Protection is off. Ask IT: it can only be re-enabled from Recovery mode.",
    windows: "Secure Boot is off. Turn it on in the device firmware (UEFI) settings, or ask IT.",
    linux: "Secure Boot is off. Turn it on in the device firmware (UEFI) settings, or ask IT.",
  },
};

export type CheckResult = { key: CheckKey; status: CheckStatus; detail: string };

/** Numeric dotted-version comparison: "14.10" > "14.9". Non-numeric parts compare as 0. */
export function compareVersions(a: string, b: string) {
  const pa = a.split(/[.\-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.\-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
}

const WORD = { disk_encryption: { macos: "FileVault", windows: "BitLocker", linux: "Disk encryption (LUKS)" }, system_integrity: { macos: "System Integrity Protection", windows: "Secure Boot", linux: "Secure Boot" } };

/** "immediately", "30 sec", "5 min". */
export const lockDelay = (seconds: number) => (seconds === 0 ? "immediately" : seconds < 60 ? `after ${seconds} sec` : `after ${Math.round(seconds / 60)} min`);

const onOff = (status: "on" | "off" | "unknown"): CheckResult["status"] => (status === "on" ? "pass" : status === "off" ? "fail" : "unknown");

/** What the organization's MDMs say about a device (DEV + MDM signals). */
export type MdmSignal = { source: string; managed: boolean; compliant: boolean | null; detail: string };
export type EvalContext = { mdmConnected: boolean; mdm: MdmSignal | null; ai?: { inventory: AIInventory | null; ctx: AIContext } };

export function evaluate(device: { platform: DevicePlatform; os_version: string; serial?: string }, facts: PostureFacts | null, policies: Policy[], ctx: EvalContext = { mdmConnected: false, mdm: null }): CheckResult[] {
  const out: CheckResult[] = [];
  for (const p of policies) {
    if (!p.enabled) continue;
    if (p.key === "mdm_compliant") {
      const m = ctx.mdm;
      if (!ctx.mdmConnected) out.push({ key: p.key, status: "not_applicable", detail: "No MDM connected" });
      else if (!m)
        out.push({
          key: p.key,
          status: "fail",
          detail: !device.serial?.trim()
            ? "Not found in your MDM (no serial number reported)"
            : usableSerial(device.serial)
              ? `Not found in your MDM (serial ${device.serial})`
              : `Can't be matched to your MDM: its serial number "${device.serial}" is a manufacturer placeholder`,
        });
      else if (!m.managed) out.push({ key: p.key, status: "fail", detail: `Not managed by ${m.source}` });
      else if (m.compliant === false) out.push({ key: p.key, status: "fail", detail: `${m.source} reports it non-compliant${m.detail ? ` (${m.detail})` : ""}` });
      else out.push({ key: p.key, status: "pass", detail: m.compliant ? `Compliant in ${m.source}` : `Managed by ${m.source}` });
      continue;
    }
    if (p.key === "ai_mcp_governed") {
      out.push(evaluateAI(p.params as z.infer<typeof PolicyParams.ai_mcp_governed>, ctx.ai));
      continue;
    }
    if (!facts && p.key !== "os_version") {
      out.push({ key: p.key, status: "unknown", detail: "Waiting for the device's first report" });
      continue;
    }
    switch (p.key) {
      case "disk_encryption": {
        const name = WORD.disk_encryption[device.platform];
        const s = facts!.disk_encryption.status;
        out.push({ key: p.key, status: onOff(s), detail: s === "on" ? `${name} is on` : s === "off" ? `${name} is off` : `Couldn't read ${name} status` });
        break;
      }
      case "firewall": {
        const s = facts!.firewall.status;
        out.push({ key: p.key, status: onOff(s), detail: s === "on" ? "Firewall is on" : s === "off" ? "Firewall is off" : "Couldn't read firewall status" });
        break;
      }
      case "screen_lock": {
        const max = Number((p.params as { max_delay_minutes?: number }).max_delay_minutes ?? 10);
        const f = facts!.screen_lock;
        if (f.status === "unknown") out.push({ key: p.key, status: "unknown", detail: "Couldn't read screen lock settings" });
        else if (f.status === "off") out.push({ key: p.key, status: "fail", detail: "Screen lock is off" });
        else if (f.delay_seconds != null && f.delay_seconds > max * 60) {
          out.push({ key: p.key, status: "fail", detail: `Locks ${lockDelay(f.delay_seconds)}; policy requires ${max === 0 ? "immediately" : `${max} min or less`}` });
        } else out.push({ key: p.key, status: "pass", detail: f.delay_seconds != null ? `Locks ${lockDelay(f.delay_seconds)}` : "Screen lock is on" });
        break;
      }
      case "os_version": {
        const min = ((p.params as { minimum?: Record<string, string> }).minimum ?? {})[device.platform] ?? "";
        if (!min) out.push({ key: p.key, status: "not_applicable", detail: "No minimum set for this platform" });
        else if (!device.os_version) out.push({ key: p.key, status: "unknown", detail: "OS version not reported" });
        else if (compareVersions(device.os_version, min) >= 0) out.push({ key: p.key, status: "pass", detail: `${device.os_version} (minimum ${min})` });
        else out.push({ key: p.key, status: "fail", detail: `${device.os_version} is older than the required ${min}` });
        break;
      }
      case "system_integrity": {
        const name = WORD.system_integrity[device.platform];
        const s = facts!.system_integrity.status;
        out.push({ key: p.key, status: onOff(s), detail: s === "on" ? `${name} is on` : s === "off" ? `${name} is off` : `Couldn't read ${name} status` });
        break;
      }
    }
  }
  return out;
}

function evaluateAI(params: z.infer<typeof PolicyParams.ai_mcp_governed>, ai: EvalContext["ai"]): CheckResult {
  const key = "ai_mcp_governed" as const;
  if (!ai?.inventory) return { key, status: "unknown", detail: "The agent hasn't reported AI tools yet (it needs a recent agent version)" };
  const active = ai.inventory.mcp_servers.filter((x) => !x.disabled);
  const problems: string[] = [];
  for (const x of active) {
    const who = `${x.name} (${x.client})`;
    const c = classify(x, ai.ctx, params.allowed_hosts);
    if (c.governance === "bypass") problems.push(`${who} connects straight to ${c.via}, bypassing the Nexus gateway`);
    else if (c.governance === "remote") problems.push(`${who} uses ${serverTarget(x).split("/")[0]}, which isn't behind the Nexus gateway`);
    else if (c.governance === "local" && !params.allow_local) problems.push(`${who} runs on the device (${x.package || x.command})`);
    if (x.inline_secrets && !params.allow_inline_secrets) problems.push(`${who} has a token written into its config file`);
  }
  if (problems.length) return { key, status: "fail", detail: problems.slice(0, 3).join("; ") + (problems.length > 3 ? `; and ${problems.length - 3} more` : "") };
  return { key, status: "pass", detail: active.length ? `${active.length} MCP server${active.length === 1 ? "" : "s"}, all approved` : "No MCP servers configured" };
}

export type EnforcedCheck = CheckResult & { enforced: boolean; failing_since: Date | null; grace_until: Date | null };

/**
 * Applies each policy's mode and grace period (DPOL-04). Audited checks are
 * reported but don't count. An enforced check that fails counts only once it
 * has been failing for longer than its grace period; until then the device
 * stays compliant and `grace_until` says by when it must be fixed.
 */
export function enforce(results: CheckResult[], policies: Policy[], previous: Map<string, { status: string; failing_since: Date | null }>, now = new Date()) {
  const checks: EnforcedCheck[] = results.map((r) => {
    const p = policies.find((x) => x.key === r.key);
    const enforced = (p?.mode ?? "enforce") === "enforce";
    const prev = previous.get(r.key);
    const failing_since = r.status === "fail" ? (prev?.status === "fail" && prev.failing_since ? prev.failing_since : now) : null;
    let grace_until: Date | null = null;
    if (failing_since && enforced && p && p.grace_hours > 0) {
      const due = new Date(failing_since.getTime() + p.grace_hours * 3600_000);
      if (due > now) grace_until = due;
    }
    return { ...r, enforced, failing_since, grace_until };
  });
  const counted = checks.filter((c) => c.enforced).map((c) => (c.grace_until ? { ...c, status: "pass" as const } : c));
  const deadlines = checks.map((c) => c.grace_until).filter((d): d is Date => !!d);
  return { checks, compliance: aggregate(counted), grace_until: deadlines.length ? new Date(Math.min(...deadlines.map((d) => d.getTime()))) : null };
}

/** Any failure → non-compliant; otherwise any unknown → unknown; otherwise compliant. */
export function aggregate(results: CheckResult[]): Compliance {
  if (results.some((r) => r.status === "fail")) return "non_compliant";
  if (results.some((r) => r.status === "unknown")) return "unknown";
  return "compliant";
}

export const fixFor = (key: CheckKey, platform: DevicePlatform) => FIX[key][platform];

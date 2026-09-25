import { z } from "@hono/zod-openapi";
import type { CheckStatus, Compliance, DevicePlatform } from "../platform/db-types.js";

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

export const CHECK_KEYS = ["disk_encryption", "firewall", "screen_lock", "os_version", "system_integrity"] as const;
export type CheckKey = (typeof CHECK_KEYS)[number];

export const PolicyParams = {
  disk_encryption: z.object({}),
  firewall: z.object({}),
  screen_lock: z.object({ max_delay_minutes: z.number().int().min(0).max(60) }),
  os_version: z.object({ minimum: z.object({ macos: z.string().max(20), windows: z.string().max(30), linux: z.string().max(20) }) }),
  system_integrity: z.object({}),
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
];

export const CHECK_INFO: Record<CheckKey, { title: string; why: string }> = {
  disk_encryption: { title: "Disk encryption", why: "A lost or stolen laptop must not expose company data." },
  firewall: { title: "Firewall", why: "Blocks unsolicited network connections to the device." },
  screen_lock: { title: "Screen lock", why: "An unattended, unlocked device is an open door." },
  os_version: { title: "Operating system up to date", why: "Old versions miss security fixes that attackers actively use." },
  system_integrity: { title: "System integrity protection", why: "SIP / Secure Boot stop malware from tampering with the OS." },
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

export function evaluate(device: { platform: DevicePlatform; os_version: string }, facts: PostureFacts | null, policies: Policy[]): CheckResult[] {
  const out: CheckResult[] = [];
  for (const p of policies) {
    if (!p.enabled) continue;
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

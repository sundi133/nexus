import { z } from "@hono/zod-openapi";

/**
 * Conditional access (SPEC CA-01..04). Pure evaluation: given the sign-in
 * (who, which app, MFA state, which device) and the org's policies, decide
 * and explain. The explanation is the product: every result says which
 * policy matched and exactly why it was or wasn't satisfied.
 */

const Ids = z.array(z.uuid()).max(500);

export const Conditions = z
  .object({
    apps: z.union([z.literal("all"), Ids.min(1)]),
    users: z.object({
      include: z.union([z.literal("all"), z.object({ groups: Ids, users: Ids }).refine((v) => v.groups.length + v.users.length > 0, "Include at least one group or user")]),
      exclude: z.object({ groups: Ids, users: Ids }).default({ groups: [], users: [] }),
    }),
  })
  .openapi("AccessConditions");
export type Conditions = z.infer<typeof Conditions>;

export const REQUIREMENTS = ["require_mfa", "require_managed_device", "require_compliant_device", "block"] as const;
export type Requirement = (typeof REQUIREMENTS)[number];

export type Policy = { id: string; name: string; enabled: boolean; mode: "report_only" | "enforce"; requirement: Requirement; conditions: Conditions };

export type DeviceState = {
  id: string;
  hostname: string;
  active: boolean;
  compliance: "compliant" | "non_compliant" | "unknown";
  lastSeenAt: Date | null;
  failing: string[]; // human-readable failing check details
};

export type Subject = {
  userId: string;
  groupIds: Set<string>;
  appId: string;
  mfa: boolean;
  device: DeviceState | null; // the device this session proved it's on, if any
};

export const STALE_AFTER_MS = 24 * 3600_000;

export type PolicyResult = {
  policy_id: string;
  name: string;
  mode: "report_only" | "enforce";
  requirement: Requirement;
  matched: boolean;
  satisfied: boolean | null; // null when the policy didn't apply
  reason: string;
};

export type Outcome = "allow" | "block" | "needs_device" | "needs_mfa";
export type Decision = { outcome: Outcome; reason: string; results: PolicyResult[] };

function matches(p: Policy, s: Subject): { matched: boolean; why: string } {
  const c = p.conditions;
  if (c.apps !== "all" && !c.apps.includes(s.appId)) return { matched: false, why: "This app isn't in the policy" };
  if (c.users.exclude.users.includes(s.userId) || c.users.exclude.groups.some((g) => s.groupIds.has(g))) {
    return { matched: false, why: "User is excluded" };
  }
  if (c.users.include !== "all") {
    const inc = c.users.include;
    if (!inc.users.includes(s.userId) && !inc.groups.some((g) => s.groupIds.has(g))) return { matched: false, why: "User isn't in the policy's groups" };
  }
  return { matched: true, why: "" };
}

/** Whether the requirement is met, and in plain words why (not). `device` issues distinguish "unknown device" from "bad device". */
function check(r: Requirement, s: Subject, now: number): { ok: boolean; reason: string; missing?: "device" | "mfa" } {
  const d = s.device;
  switch (r) {
    case "block":
      return { ok: false, reason: "Access to this app is blocked by policy" };
    case "require_mfa":
      return s.mfa ? { ok: true, reason: "Signed in with MFA" } : { ok: false, reason: "This app requires multi-factor authentication", missing: "mfa" };
    case "require_managed_device":
      if (!d) return { ok: false, reason: "This app requires a device managed by Nexus", missing: "device" };
      if (!d.active) return { ok: false, reason: `${d.hostname} is no longer managed` };
      return { ok: true, reason: `On managed device ${d.hostname}` };
    case "require_compliant_device": {
      if (!d) return { ok: false, reason: "This app requires a compliant device managed by Nexus", missing: "device" };
      if (!d.active) return { ok: false, reason: `${d.hostname} is no longer managed` };
      if (!d.lastSeenAt || now - d.lastSeenAt.getTime() > STALE_AFTER_MS) {
        return { ok: false, reason: `${d.hostname} hasn't reported in over 24 hours, so its compliance is unknown` };
      }
      if (d.compliance === "compliant") return { ok: true, reason: `${d.hostname} is compliant` };
      if (d.compliance === "unknown") return { ok: false, reason: `${d.hostname}'s compliance couldn't be confirmed` };
      return { ok: false, reason: `${d.hostname} isn't compliant: ${d.failing.join("; ") || "a device policy is failing"}` };
    }
  }
}

/**
 * Enforced policies decide; report-only policies are evaluated and recorded but never act.
 * Precedence among unmet enforced requirements: block → prove device → device problems → MFA.
 */
export function evaluate(policies: Policy[], s: Subject, now = Date.now()): Decision {
  const results: PolicyResult[] = [];
  const unmet: { r: PolicyResult; missing?: "device" | "mfa" }[] = [];
  for (const p of policies) {
    if (!p.enabled) continue;
    const m = matches(p, s);
    if (!m.matched) {
      results.push({ policy_id: p.id, name: p.name, mode: p.mode, requirement: p.requirement, matched: false, satisfied: null, reason: m.why });
      continue;
    }
    const c = check(p.requirement, s, now);
    const r: PolicyResult = { policy_id: p.id, name: p.name, mode: p.mode, requirement: p.requirement, matched: true, satisfied: c.ok, reason: c.reason };
    results.push(r);
    if (!c.ok && p.mode === "enforce") unmet.push({ r, missing: c.missing });
  }
  const pick = (f: (u: (typeof unmet)[number]) => boolean) => unmet.find(f);
  const block = pick((u) => u.r.requirement === "block");
  if (block) return { outcome: "block", reason: block.r.reason, results };
  const needDevice = pick((u) => u.missing === "device");
  if (needDevice) return { outcome: "needs_device", reason: needDevice.r.reason, results };
  const badDevice = pick((u) => u.r.requirement !== "require_mfa");
  if (badDevice) return { outcome: "block", reason: badDevice.r.reason, results };
  const needMfa = pick((u) => u.missing === "mfa");
  if (needMfa) return { outcome: "needs_mfa", reason: needMfa.r.reason, results };
  return { outcome: "allow", reason: "No enforced policy blocks this sign-in", results };
}

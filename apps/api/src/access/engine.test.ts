import { describe, expect, it } from "vitest";
import { evaluate, type DeviceState, type Policy, type Subject } from "./engine.js";

const APP = "00000000-0000-7000-8000-00000000a001";
const OTHER_APP = "00000000-0000-7000-8000-00000000a002";
const ENG = "00000000-0000-7000-8000-00000000e001";
const CONTRACTORS = "00000000-0000-7000-8000-00000000c001";
const USER = "00000000-0000-7000-8000-00000000u001".replace("u", "0");

const everyone = { include: "all" as const, exclude: { groups: [], users: [] } };
const policy = (p: Partial<Policy> & Pick<Policy, "requirement">): Policy => ({
  id: crypto.randomUUID(),
  name: p.requirement,
  enabled: true,
  mode: "enforce",
  conditions: { apps: "all", users: everyone },
  ...p,
});
const device = (d: Partial<DeviceState> = {}): DeviceState => ({ id: "d1", hostname: "MacBook Air", active: true, compliance: "compliant", lastSeenAt: new Date(), failing: [], ...d });
const subject = (s: Partial<Subject> = {}): Subject => ({ userId: USER, groupIds: new Set([ENG]), appId: APP, mfa: true, device: device(), ...s });

describe("conditional access", () => {
  it("allows when nothing applies", () => {
    expect(evaluate([], subject()).outcome).toBe("allow");
  });

  it("asks the browser to prove its device before judging it", () => {
    const d = evaluate([policy({ requirement: "require_compliant_device" })], subject({ device: null }));
    expect(d).toMatchObject({ outcome: "needs_device", reason: "This app requires a compliant device managed by Nexus" });
  });

  it("blocks a non-compliant device and says exactly why", () => {
    const d = evaluate([policy({ requirement: "require_compliant_device" })], subject({ device: device({ compliance: "non_compliant", failing: ["FileVault is off", "Firewall is off"] }) }));
    expect(d).toMatchObject({ outcome: "block", reason: "MacBook Air isn't compliant: FileVault is off; Firewall is off" });
  });

  it("treats a device that stopped reporting as unknown, not compliant", () => {
    const stale = device({ lastSeenAt: new Date(Date.now() - 25 * 3600_000) });
    expect(evaluate([policy({ requirement: "require_compliant_device" })], subject({ device: stale })).outcome).toBe("block");
    expect(evaluate([policy({ requirement: "require_managed_device" })], subject({ device: stale })).outcome).toBe("allow");
  });

  it("report-only policies record what would happen but never act", () => {
    const d = evaluate([policy({ requirement: "block", mode: "report_only" })], subject());
    expect(d.outcome).toBe("allow");
    expect(d.results[0]).toMatchObject({ matched: true, satisfied: false, mode: "report_only" });
  });

  it("scopes by app, group and exclusions", () => {
    const p = policy({ requirement: "block", conditions: { apps: [OTHER_APP], users: everyone } });
    expect(evaluate([p], subject()).results[0]).toMatchObject({ matched: false, reason: "This app isn't in the policy" });
    const contractorsOnly = policy({ requirement: "block", conditions: { apps: "all", users: { include: { groups: [CONTRACTORS], users: [] }, exclude: { groups: [], users: [] } } } });
    expect(evaluate([contractorsOnly], subject()).outcome).toBe("allow");
    expect(evaluate([contractorsOnly], subject({ groupIds: new Set([CONTRACTORS]) })).outcome).toBe("block");
    const excludeEng = policy({ requirement: "block", conditions: { apps: "all", users: { include: "all", exclude: { groups: [ENG], users: [] } } } });
    expect(evaluate([excludeEng], subject()).results[0]!.reason).toBe("User is excluded");
  });

  it("orders requirements: block, then device proof, then device health, then MFA", () => {
    const all = [policy({ requirement: "require_mfa" }), policy({ requirement: "require_compliant_device" })];
    expect(evaluate(all, subject({ mfa: false, device: null })).outcome).toBe("needs_device");
    expect(evaluate(all, subject({ mfa: false })).outcome).toBe("needs_mfa");
    expect(evaluate(all, subject({ mfa: false, device: device({ compliance: "non_compliant" }) })).outcome).toBe("block");
    expect(evaluate([...all, policy({ requirement: "block" })], subject()).outcome).toBe("block");
  });

  it("ignores disabled policies", () => {
    expect(evaluate([policy({ requirement: "block", enabled: false })], subject()).outcome).toBe("allow");
  });
});

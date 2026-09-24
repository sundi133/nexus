import { describe, expect, it } from "vitest";
import { aggregate, compareVersions, DEFAULT_POLICIES, evaluate, type PostureFacts } from "./posture.js";

const good: PostureFacts = {
  disk_encryption: { status: "on" },
  firewall: { status: "on" },
  screen_lock: { status: "on", delay_seconds: 300 },
  system_integrity: { status: "on" },
};
const mac = { platform: "macos" as const, os_version: "15.1" };

describe("compareVersions", () => {
  it("compares numerically, not lexically", () => {
    expect(compareVersions("14.10", "14.9")).toBe(1);
    expect(compareVersions("14.0", "14")).toBe(0);
    expect(compareVersions("10.0.19045", "10.0.22631")).toBe(-1);
    expect(compareVersions("13.6.1", "14.0")).toBe(-1);
  });
});

describe("evaluate", () => {
  it("passes a healthy Mac", () => {
    const r = evaluate(mac, good, DEFAULT_POLICIES);
    expect(r.every((c) => c.status === "pass")).toBe(true);
    expect(aggregate(r)).toBe("compliant");
  });

  it("explains each failure", () => {
    const r = evaluate({ platform: "macos", os_version: "13.6" }, { ...good, disk_encryption: { status: "off" }, screen_lock: { status: "on", delay_seconds: 3600 } }, DEFAULT_POLICIES);
    const byKey = Object.fromEntries(r.map((c) => [c.key, c]));
    expect(byKey.disk_encryption).toMatchObject({ status: "fail", detail: "FileVault is off" });
    expect(byKey.screen_lock).toMatchObject({ status: "fail", detail: "Locks after 60 min; policy requires 10 min or less" });
    expect(byKey.os_version).toMatchObject({ status: "fail", detail: "13.6 is older than the required 14.0" });
    expect(aggregate(r)).toBe("non_compliant");
  });

  it("describes lock delays in plain words", () => {
    const at = (delay_seconds: number) => evaluate(mac, { ...good, screen_lock: { status: "on", delay_seconds } }, DEFAULT_POLICIES).find((c) => c.key === "screen_lock")!.detail;
    expect(at(0)).toBe("Locks immediately");
    expect(at(30)).toBe("Locks after 30 sec");
    expect(at(300)).toBe("Locks after 5 min");
  });

  it("treats unreadable facts as unknown, never as compliant", () => {
    const r = evaluate(mac, { ...good, firewall: { status: "unknown" } }, DEFAULT_POLICIES);
    expect(aggregate(r)).toBe("unknown");
    expect(aggregate(evaluate(mac, null, DEFAULT_POLICIES))).toBe("unknown");
  });

  it("uses platform wording and skips disabled checks and unset minimums", () => {
    const policies = DEFAULT_POLICIES.map((p) => (p.key === "firewall" ? { ...p, enabled: false } : p));
    const r = evaluate({ platform: "linux", os_version: "6.8" }, { ...good, disk_encryption: { status: "off" } }, policies);
    expect(r.find((c) => c.key === "firewall")).toBeUndefined();
    expect(r.find((c) => c.key === "disk_encryption")!.detail).toBe("Disk encryption (LUKS) is off");
    expect(r.find((c) => c.key === "os_version")!.status).toBe("not_applicable");
  });
});

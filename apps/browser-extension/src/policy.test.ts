import { describe as group, expect, it } from "vitest";
import { appFor, check, countSaas, describe, dlpEvents, navigationRules, type Policy, saasFor } from "./policy.js";

const policy: Policy = {
  version: "v1",
  apps: [
    { key: "chatgpt", name: "ChatGPT", hosts: ["chatgpt.com", "chat.openai.com"], action: "allow" },
    { key: "deepseek", name: "DeepSeek", hosts: ["chat.deepseek.com"], action: "block" },
    { key: "character_ai", name: "Character.AI", hosts: ["character.ai"], action: "warn" },
  ],
  dlp: { detectors: { secret: "block", credit_card: "warn", us_ssn: "monitor", iban: "off" }, custom: [{ id: "falcon", name: "Project Falcon", pattern: "project\\s+falcon", action: "warn" }] },
  uploads: "warn",
  message: "",
};

group("policy", () => {
  it("maps hosts and subdomains to apps, and nothing else", () => {
    expect(appFor(policy, "chatgpt.com")?.key).toBe("chatgpt");
    expect(appFor(policy, "www.chatgpt.com")?.key).toBe("chatgpt");
    expect(appFor(policy, "CHAT.OPENAI.COM.")?.key).toBe("chatgpt");
    expect(appFor(policy, "notchatgpt.com")).toBeNull();
    expect(appFor(policy, "openai.com")).toBeNull();
    expect(appFor(null, "chatgpt.com")).toBeNull();
  });

  it("takes the strictest action among the findings", () => {
    expect(check(policy, "hello").action).toBe("off");
    expect(check(policy, "SSN 123-45-6789").action).toBe("monitor");
    expect(check(policy, "card 4242 4242 4242 4242 and SSN 123-45-6789").action).toBe("warn");
    const v = check(policy, "card 4242 4242 4242 4242, key AKIAIOSFODNN7EXAMPLE, Project Falcon");
    expect(v.action).toBe("block");
    expect(describe(v)).toBe("AWS access key, Payment card number and Project Falcon");
    expect(check(policy, "DE89 3704 0044 0532 0130 00").action).toBe("off"); // detector off
  });

  it("reports the detector and a masked hint, never the text", () => {
    const v = check(policy, "my key is AKIAIOSFODNN7EXAMPLE please debug");
    const e = dlpEvents(v, "chatgpt", "chatgpt.com", "blocked", new Date("2026-09-27T00:00:00Z"));
    expect(e).toEqual([{ at: "2026-09-27T00:00:00.000Z", kind: "dlp", action: "blocked", app: "chatgpt", host: "chatgpt.com", detector: "secret", count: 1, detail: "AWS access key AKIA…LE" }]);
    expect(JSON.stringify(e)).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("redirects blocked and warned apps to the interstitial, keeping the address, except hosts allowed for now", () => {
    const rules = navigationRules(policy, "chrome-extension://abc") as any[];
    expect(rules).toHaveLength(2);
    expect(rules[0].action.redirect.regexSubstitution).toBe("chrome-extension://abc/interstitial.html?mode=block&app=deepseek#\\0");
    const re = new RegExp(rules[0].condition.regexFilter);
    expect(re.test("https://chat.deepseek.com/a/chat/s/123")).toBe(true);
    expect(re.test("https://chat.deepseek.com")).toBe(true);
    expect(re.test("https://evilchat.deepseek.com.attacker.io/")).toBe(false);
    expect(re.test("https://chat-deepseek.com/")).toBe(false);
    expect(navigationRules(policy, "chrome-extension://abc", ["character.ai"])).toHaveLength(1);
  });
});

group("SaaS discovery", () => {
  const withSaas: Policy = { ...policy, saas: { discovery: true, apps: [{ key: "zoom", hosts: ["zoom.us"] }, { key: "zoom-events", hosts: ["events.zoom.us"] }, { key: "slack", hosts: ["slack.com"] }] } };

  it("maps a host to the most specific app, only while discovery is on", () => {
    expect(saasFor(withSaas, "acme.zoom.us")).toBe("zoom");
    expect(saasFor(withSaas, "events.zoom.us")).toBe("zoom-events");
    expect(saasFor(withSaas, "app.slack.com")).toBe("slack");
    expect(saasFor(withSaas, "notslack.com")).toBeNull();
    expect(saasFor({ ...withSaas, saas: { ...withSaas.saas!, discovery: false } }, "slack.com")).toBeNull();
    expect(saasFor(policy, "slack.com")).toBeNull();
  });

  it("counts into one event per app per day, with no address", () => {
    const d1 = new Date("2026-09-27T10:00:00Z");
    let q = countSaas([], "saas", "slack", d1);
    q = countSaas(q, "saas", "slack", new Date("2026-09-27T11:00:00Z"));
    q = countSaas(q, "saas_login", "slack", d1);
    q = countSaas(q, "saas", "slack", new Date("2026-09-28T09:00:00Z"));
    expect(q.map((e) => [e.kind, e.app, e.count ?? 1, e.at.slice(0, 10), e.host])).toEqual([
      ["saas", "slack", 2, "2026-09-27", ""],
      ["saas_login", "slack", 1, "2026-09-27", ""],
      ["saas", "slack", 1, "2026-09-28", ""],
    ]);
  });
});

import { type Custom, type Finding, scan } from "./detectors.js";

/** The organization's policy, as the server sends it. */
export type AppAction = "allow" | "warn" | "block";
export type DlpAction = "off" | "monitor" | "warn" | "block";
export type Policy = {
  version: string;
  apps: { key: string; name: string; hosts: string[]; action: AppAction }[];
  dlp: { detectors: Record<string, DlpAction>; custom: (Custom & { action: DlpAction })[] };
  uploads: AppAction;
  message: string;
};

export type Event = {
  at: string;
  kind: "visit" | "dlp" | "upload";
  action: "allowed" | "monitored" | "warned" | "continued" | "blocked";
  app: string;
  host: string;
  detector?: string;
  count?: number;
  detail?: string;
};

/** The catalog app a host belongs to (the host itself or a subdomain of one of its hosts). */
export function appFor(policy: Policy | null, hostname: string) {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  return policy?.apps.find((a) => a.hosts.some((x) => h === x || h.endsWith(`.${x}`))) ?? null;
}

const RANK: Record<DlpAction, number> = { off: 0, monitor: 1, warn: 2, block: 3 };

export type Verdict = { action: DlpAction; findings: (Finding & { action: DlpAction })[] };

/** Scans text and decides: the strictest action among what was found wins. */
export function check(policy: Policy, text: string): Verdict {
  const enabled = Object.entries(policy.dlp.detectors).filter(([, a]) => a !== "off").map(([id]) => id);
  const custom = policy.dlp.custom.filter((c) => c.action !== "off");
  const actionOf = (detector: string): DlpAction =>
    detector.startsWith("custom:") ? (custom.find((c) => `custom:${c.id}` === detector)?.action ?? "off") : (policy.dlp.detectors[detector] ?? "off");
  const findings = scan(text, enabled, custom).map((f) => ({ ...f, action: actionOf(f.detector) }));
  const action = findings.reduce<DlpAction>((a, f) => (RANK[f.action] > RANK[a] ? f.action : a), "off");
  return { action, findings };
}

/** One line for people ("an AWS access key and a payment card number") and for the report. */
export function describe(v: Verdict): string {
  const names = [...new Set(v.findings.map((f) => f.name))];
  return names.length <= 2 ? names.join(" and ") : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;
}

/** Events from one verdict, for the report: the detector and a masked hint, never the text. */
export function dlpEvents(v: Verdict, app: string, host: string, action: Event["action"], at = new Date()): Event[] {
  return v.findings.map((f) => ({ at: at.toISOString(), kind: "dlp", action, app, host, detector: f.detector, count: f.count, detail: `${f.name} ${f.hint}`.slice(0, 300) }));
}

/** Builds the declarativeNetRequest rules for blocked and warned apps (interstitial page). */
export function navigationRules(policy: Policy, extensionOrigin: string, allowHosts: readonly string[] = []) {
  const rules: object[] = [];
  let id = 1;
  for (const app of policy.apps) {
    if (app.action === "allow") continue;
    const hosts = app.hosts.filter((h) => !allowHosts.includes(h));
    if (!hosts.length) continue;
    const alternation = hosts.map((h) => h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
    rules.push({
      id: id++,
      priority: 1,
      action: { type: "redirect", redirect: { regexSubstitution: `${extensionOrigin}/interstitial.html?mode=${app.action}&app=${app.key}#\\0` } },
      condition: { regexFilter: `^https?://([^/]*\\.)?(${alternation})(:\\d+)?(/.*)?$`, resourceTypes: ["main_frame"] },
    });
  }
  return rules;
}

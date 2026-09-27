import { type Custom, type Finding, scan } from "@nexus/dlp";

/** The organization's policy, as the server sends it. */
export type AppAction = "allow" | "warn" | "block";
export type DlpAction = "off" | "monitor" | "warn" | "block";
export type Policy = {
  version: string;
  apps: { key: string; name: string; hosts: string[]; action: AppAction; kind?: "ai" | "saas" }[];
  dlp: { detectors: Record<string, DlpAction>; custom: (Custom & { action: DlpAction })[] };
  uploads: AppAction;
  message: string;
  /** SaaS discovery: which hosts belong to which app (empty while discovery is off). */
  saas?: { discovery: boolean; apps: { key: string; hosts: string[] }[] };
};

export type Event = {
  at: string;
  kind: "visit" | "dlp" | "upload" | "saas" | "saas_login";
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

/** The SaaS app a host belongs to, while discovery is on: the most specific (longest) host wins. */
export function saasFor(policy: Policy | null, hostname: string) {
  if (!policy?.saas?.discovery) return null;
  const h = hostname.toLowerCase().replace(/\.$/, "");
  let best: string | null = null;
  let len = 0;
  for (const a of policy.saas.apps) {
    for (const x of a.hosts) {
      if ((h === x || h.endsWith(`.${x}`)) && x.length > len) {
        best = a.key;
        len = x.length;
      }
    }
  }
  return best;
}

/**
 * Adds one SaaS visit or sign-in to the queue: counted into the same app's event for the same day
 * (UTC), so a busy day is one event per app, and only the app and the count are ever reported.
 */
export function countSaas(queue: Event[], kind: "saas" | "saas_login", app: string, now = new Date()): Event[] {
  const day = now.toISOString().slice(0, 10);
  const i = queue.findIndex((e) => e.kind === kind && e.app === app && e.at.slice(0, 10) === day);
  if (i >= 0) {
    const next = queue.slice();
    next[i] = { ...next[i]!, count: (next[i]!.count ?? 1) + 1, at: now.toISOString() };
    return next;
  }
  return [...queue, { at: now.toISOString(), kind, action: "allowed", app, host: "" }];
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

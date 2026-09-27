import { AI_APPS } from "../browser/catalog.js";
import { DATA } from "./catalog-data.js";

/**
 * SaaS apps Nexus recognises: for discovery in browsers (who uses what), the app directory in
 * Applications, and license tracking. AI apps have their own catalog (browser/catalog.ts) with
 * sensitive-data protection; a host belongs to one app only.
 */
export type SaasApp = { key: string; name: string; category: string; hosts: string[] };

const HOST = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export const slug = (name: string) =>
  name
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/\+/g, " plus ")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40);

function parse(): SaasApp[] {
  const taken = new Set(AI_APPS.flatMap((a) => a.hosts));
  const keys = new Set(AI_APPS.map((a) => a.key));
  const out: SaasApp[] = [];
  let category = "";
  for (const line of DATA.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    if (t.startsWith("## ")) {
      category = t.slice(3);
      continue;
    }
    const i = t.indexOf(": ");
    const name = t.slice(0, i);
    // Hosts only (a path can't be told apart in a navigation), each owned by the first app listing it.
    const hosts = t
      .slice(i + 2)
      .split(/\s+/)
      .filter((h) => HOST.test(h) && !taken.has(h));
    const key = slug(name);
    if (!hosts.length || keys.has(key)) continue;
    hosts.forEach((h) => taken.add(h));
    keys.add(key);
    out.push({ key, name, category, hosts });
  }
  return out;
}

export const SAAS_APPS: SaasApp[] = parse();
export const SAAS_BY_KEY = new Map(SAAS_APPS.map((a) => [a.key, a]));
export const SAAS_CATEGORIES = [...new Set(SAAS_APPS.map((a) => a.category))];

/** The app a host belongs to: the most specific (longest) matching host wins. */
export function saasFor(hostname: string): SaasApp | null {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  let best: SaasApp | null = null;
  let len = 0;
  for (const a of SAAS_APPS) {
    for (const x of a.hosts) {
      if ((h === x || h.endsWith(`.${x}`)) && x.length > len) {
        best = a;
        len = x.length;
      }
    }
  }
  return best;
}

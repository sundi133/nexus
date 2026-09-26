import { createHash, randomBytes, randomUUID, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { ZodError } from "zod";
import type { Config } from "../config.js";
import type { Deps } from "../context.js";
import { send as page } from "../alerts/oncall.js";
import { fetchIntune, fetchJamf, type MdmDevice } from "../devices/mdm-providers.js";
import { usableSerial } from "../devices/serial.js";
import { fetchLdap } from "../directory/sync/ldap.js";
import { type Remote, plan, summarize } from "../directory/sync/plan.js";
import { fetchEntra, fetchGoogle } from "../directory/sync/providers.js";
import { discover } from "../federation/oidc-rp.js";
import { parseIdpMetadata } from "../federation/saml-sp.js";
import { send as sendEvents } from "../integrations/senders.js";
import { assertSafeUrl } from "../platform/outbound.js";

/**
 * Live vendor check: runs Nexus's production connectors against real tenants
 * (Entra ID, Google, AD/LDAP, Okta/Entra sign-in metadata, Intune, Jamf,
 * PagerDuty, Opsgenie, Sentinel, S3) and reports what a pilot would hit —
 * errors, permissions, and data quirks — as a redacted report that's safe to
 * share: counts and findings, with emails, IDs and secrets hashed or removed.
 *
 * Read-only against directories and MDMs. Paging and event delivery send one
 * clearly labelled test each, and only when asked (--page, --send-events).
 */

export type Status = "ok" | "warn" | "fail" | "skipped";
export type CheckResult = { check: string; status: Status; ms: number; stats: Record<string, unknown>; findings: string[]; error?: string };
export type Report = { tool: "nexus-live-check"; version: 1; ran_at: string; node: string; summary: Record<Status, number>; checks: CheckResult[] };
export type Options = { page: boolean; sendEvents: boolean; only: string[] | null; allowPrivate: boolean };

type Env = Record<string, string | undefined>;
type Ctx = { env: Env; cfg: Config; opts: Options; directoryEmails: Set<string> };

const DAY = 86_400_000;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

class Finding {
  readonly list: string[] = [];
  add(n: number, what: string) {
    if (n > 0) this.list.push(`${n} ${what}`);
  }
  note(what: string) {
    this.list.push(what);
  }
}
class Warn extends Error {}

const pct = (n: number, of: number) => (of ? Math.round((n / of) * 1000) / 10 : 0);
function countBy<T>(xs: T[], key: (x: T) => string) {
  const out: Record<string, number> = {};
  for (const x of xs) out[key(x)] = (out[key(x)] ?? 0) + 1;
  return out;
}
const dupes = (xs: string[]) => {
  const seen = countBy(xs.filter(Boolean), (x) => x);
  return Object.values(seen).filter((n) => n > 1).reduce((a, n) => a + n, 0);
};
const need = (env: Env, ...names: string[]) => names.every((n) => !!env[n]?.trim());

// ---- Directories -----------------------------------------------------------------------------

function directoryQuirks(remote: Remote, f: Finding) {
  const users = remote.users;
  const emails = users.map((u) => u.email.trim().toLowerCase());
  f.add(users.filter((u) => !u.email.trim()).length, "people have no email (they can't be created in Nexus)");
  f.add(users.filter((u) => u.email.trim() && !EMAIL.test(u.email.trim())).length, "people have a malformed email");
  f.add(dupes(emails), "people share an email with someone else (case-insensitive)");
  f.add(users.filter((u) => /#ext#/i.test(u.email)).length, "people have a guest-style #EXT# address");
  f.add(users.filter((u) => /\.onmicrosoft\.com$/i.test(u.email)).length, "people have only an .onmicrosoft.com address (no mail attribute)");
  f.add(users.filter((u) => /[^\x20-\x7e]/.test(u.email)).length, "emails contain non-ASCII characters");
  f.add(users.filter((u) => u.email !== u.email.trim()).length, "emails have leading or trailing spaces");
  f.add(users.filter((u) => !u.given_name.trim() && !u.family_name.trim()).length, "people have no name");
  const ids = new Set(users.map((u) => u.external_id));
  f.add(remote.groups.filter((g) => g.member_ids.length === 0).length, "groups are empty");
  f.add(remote.groups.filter((g) => g.member_ids.length > 5000).length, "groups have more than 5,000 members");
  f.add(dupes(remote.groups.map((g) => g.name.toLowerCase())), "groups share a name");
  const orphan = new Set(remote.groups.flatMap((g) => g.member_ids.filter((m) => !ids.has(m))));
  f.add(orphan.size, "group members aren't among the people read (guests, out of scope, or filtered)");
}

function directoryStats(remote: Remote, ctx: Ctx, f: Finding, provider: "entra" | "google" | "ldap") {
  directoryQuirks(remote, f);
  for (const u of remote.users) if (u.email) ctx.directoryEmails.add(u.email.trim().toLowerCase());
  const p = plan(remote, { users: [], groups: [], links: [] }, { provider, deprovision: "suspend", sync_groups: true, group_filter: [] });
  const skipped = countBy(p.skipped, (s) => s.reason);
  for (const [reason, n] of Object.entries(skipped)) f.add(n, `would be skipped by a first sync: ${reason}`);
  const domains = countBy(remote.users.filter((u) => u.email.includes("@")), (u) => u.email.split("@")[1]!.toLowerCase());
  return {
    users: remote.users.length,
    active: remote.users.filter((u) => u.active).length,
    inactive: remote.users.filter((u) => !u.active).length,
    with_title: pct(remote.users.filter((u) => u.title).length, remote.users.length),
    with_department: pct(remote.users.filter((u) => u.department).length, remote.users.length),
    groups: remote.groups.length,
    largest_group: Math.max(0, ...remote.groups.map((g) => g.member_ids.length)),
    memberships: remote.groups.reduce((n, g) => n + g.member_ids.length, 0),
    email_domains: Object.fromEntries(Object.entries(domains).sort((a, b) => b[1] - a[1]).slice(0, 10)),
    first_sync_would: summarize(p),
  };
}

async function entraDirectory(ctx: Ctx, f: Finding) {
  const { env } = ctx;
  if (!need(env, "LIVE_ENTRA_TENANT_ID", "LIVE_ENTRA_CLIENT_ID", "LIVE_ENTRA_CLIENT_SECRET")) return null;
  const remote = await fetchEntra(ctx.cfg, { tenant_id: env.LIVE_ENTRA_TENANT_ID, client_id: env.LIVE_ENTRA_CLIENT_ID }, env.LIVE_ENTRA_CLIENT_SECRET!, { groups: true });
  return directoryStats(remote, ctx, f, "entra");
}

async function googleDirectory(ctx: Ctx, f: Finding) {
  const { env } = ctx;
  if (!need(env, "LIVE_GOOGLE_ADMIN_EMAIL", "LIVE_GOOGLE_KEY_FILE")) return null;
  const key = readFileSync(env.LIVE_GOOGLE_KEY_FILE!, "utf8");
  const remote = await fetchGoogle(ctx.cfg, { admin_email: env.LIVE_GOOGLE_ADMIN_EMAIL, customer_id: env.LIVE_GOOGLE_CUSTOMER_ID || "my_customer" }, key, { groups: true });
  return directoryStats(remote, ctx, f, "google");
}

async function ldapDirectory(ctx: Ctx, f: Finding) {
  const { env } = ctx;
  if (!need(env, "LIVE_LDAP_URL", "LIVE_LDAP_BIND_DN", "LIVE_LDAP_PASSWORD", "LIVE_LDAP_BASE_DN")) return null;
  const cfg = {
    preset: env.LIVE_LDAP_PRESET || "active_directory",
    url: env.LIVE_LDAP_URL,
    start_tls: env.LIVE_LDAP_START_TLS === "true",
    ca_cert: env.LIVE_LDAP_CA_FILE ? readFileSync(env.LIVE_LDAP_CA_FILE, "utf8") : undefined,
    bind_dn: env.LIVE_LDAP_BIND_DN,
    base_dn: env.LIVE_LDAP_BASE_DN,
    user_search_filter: env.LIVE_LDAP_USER_FILTER || undefined,
    group_search_filter: env.LIVE_LDAP_GROUP_FILTER || undefined,
  };
  if (/^ldap:\/\//i.test(cfg.url!) && !cfg.start_tls) f.note("the connection is plain ldap:// without StartTLS: passwords would cross the network in clear (use ldaps:// or StartTLS)");
  const remote = await fetchLdap({ cfg: ctx.cfg }, cfg, env.LIVE_LDAP_PASSWORD!, { groups: true });
  return directoryStats(remote, ctx, f, "ldap");
}

// ---- Sign-in ---------------------------------------------------------------------------------

async function getJson(url: string) {
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000), redirect: "error" });
  if (!res.ok) throw new Error(`${new URL(url).host} answered HTTP ${res.status}`);
  return (await res.json()) as any;
}

async function oidc(ctx: Ctx, f: Finding) {
  const issuers = (ctx.env.LIVE_OIDC_ISSUERS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!issuers.length) return null;
  const out: Record<string, unknown>[] = [];
  let failed = 0;
  for (const [i, issuer] of issuers.entries()) {
    const label = `issuer ${i + 1} (${new URL(issuer).host})`;
    try {
      const d = await discover(issuer, ctx.opts.allowPrivate, true);
      const full = await getJson(`${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`);
      const jwks = await getJson(d.jwks_uri);
      const algs: string[] = full.id_token_signing_alg_values_supported ?? [];
      const claims: string[] = full.claims_supported ?? [];
      if (!algs.includes("RS256") && !algs.includes("ES256")) f.note(`${label}: signs ID tokens with ${algs.join(", ") || "nothing advertised"}, not RS256/ES256`);
      if (claims.length && !claims.includes("email")) f.note(`${label}: doesn't advertise an email claim (Nexus matches people by email)`);
      out.push({ issuer: label, ok: true, keys: (jwks.keys ?? []).length, algs, email_claim: claims.length ? claims.includes("email") : "not advertised", groups_claim: claims.includes("groups") });
    } catch (e) {
      failed++;
      out.push({ issuer: label, ok: false, error: (e as Error).message });
    }
  }
  if (failed) throw new Error(`${failed} of ${issuers.length} issuers failed: ${out.filter((o) => !o.ok).map((o) => `${o.issuer}: ${o.error}`).join("; ")}`);
  return { issuers: out };
}

async function saml(ctx: Ctx, f: Finding) {
  const urls = (ctx.env.LIVE_SAML_METADATA_URLS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!urls.length) return null;
  const out: Record<string, unknown>[] = [];
  for (const [i, url] of urls.entries()) {
    const label = `metadata ${i + 1} (${new URL(url).host})`;
    await assertSafeUrl(url, { allowPrivate: ctx.opts.allowPrivate });
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000), redirect: "error" });
    if (!res.ok) throw new Error(`${label}: HTTP ${res.status}`);
    const xml = await res.text();
    const md = parseIdpMetadata(xml);
    const expiries = md.certs.map((pem) => new Date(new X509Certificate(pem).validTo));
    for (const e of expiries) {
      const days = Math.floor((e.getTime() - Date.now()) / DAY);
      if (days < 0) f.note(`${label}: a signing certificate expired ${-days} days ago`);
      else if (days < 60) f.note(`${label}: a signing certificate expires in ${days} days (plan the rollover)`);
    }
    if (md.certs.length > 1) f.note(`${label}: ${md.certs.length} signing certificates (a rollover in progress; Nexus accepts each)`);
    if (/SignatureMethod[^>]+rsa-sha1|DigestMethod[^>]+#sha1/.test(xml)) f.note(`${label}: the metadata mentions SHA-1; Nexus refuses SHA-1 assertions, so set the app to SHA-256`);
    out.push({ metadata: label, sso_host: new URL(md.sso_url).host, certificates: md.certs.length, earliest_expiry_days: Math.min(...expiries.map((e) => Math.floor((e.getTime() - Date.now()) / DAY))) });
  }
  return { metadata: out };
}

// ---- Devices ---------------------------------------------------------------------------------

function mdmStats(devices: MdmDevice[], ctx: Ctx, f: Finding) {
  const serials = devices.map((d) => d.serial.trim().toLowerCase());
  const placeholders = devices.filter((d) => d.serial.trim() && !usableSerial(d.serial));
  f.add(devices.filter((d) => !d.serial.trim()).length, "devices have no serial number (Nexus can't match them to agents)");
  f.add(placeholders.length, `devices report a placeholder serial${placeholders.length ? ` (e.g. "${placeholders[0]!.serial}")` : ""} and won't be matched`);
  f.add(dupes(serials.filter((s) => usableSerial(s))), "devices share a serial with another record (duplicates or re-enrollments; they won't be matched)");
  f.add(devices.filter((d) => !d.user_email).length, "devices have no user");
  f.add(devices.filter((d) => d.compliant === null).length, "devices have no compliance verdict (unknown, or Jamf without a FileVault state)");
  f.add(devices.filter((d) => !d.managed).length, "devices are unmanaged or pending retire/wipe");
  f.add(devices.filter((d) => !d.last_contact_at).length, "devices have never checked in with the MDM");
  f.add(devices.filter((d) => d.last_contact_at && Date.now() - d.last_contact_at.getTime() > 30 * DAY).length, "devices haven't checked in with the MDM for 30+ days");
  const details = countBy(devices.filter((d) => d.compliance_detail), (d) => d.compliance_detail);
  for (const [detail, n] of Object.entries(details)) if (!/grace period|FileVault is off|conflicting|policy error|Configuration Manager/.test(detail)) f.add(n, `devices have a compliance state Nexus doesn't know: "${detail}"`);
  if (ctx.directoryEmails.size) {
    const users = devices.filter((d) => d.user_email);
    f.add(users.filter((d) => !ctx.directoryEmails.has(d.user_email)).length, "devices' users aren't in the directory read above (UPN vs. mail mismatch?)");
  }
  return {
    devices: devices.length,
    by_platform: countBy(devices, (d) => d.platform || "unknown"),
    compliant: devices.filter((d) => d.compliant === true).length,
    noncompliant: devices.filter((d) => d.compliant === false).length,
    unknown: devices.filter((d) => d.compliant === null).length,
    usable_serials: pct(devices.filter((d) => usableSerial(d.serial)).length, devices.length),
    encrypted_known: pct(devices.filter((d) => d.encrypted !== null).length, devices.length),
    with_management_id: pct(devices.filter((d) => d.management_id).length, devices.length),
  };
}

async function intune(ctx: Ctx, f: Finding) {
  const e = ctx.env;
  const tenant = e.LIVE_INTUNE_TENANT_ID || e.LIVE_ENTRA_TENANT_ID;
  const client = e.LIVE_INTUNE_CLIENT_ID || e.LIVE_ENTRA_CLIENT_ID;
  const secret = e.LIVE_INTUNE_CLIENT_SECRET || e.LIVE_ENTRA_CLIENT_SECRET;
  if (!tenant || !client || !secret || !(e.LIVE_INTUNE_TENANT_ID || e.LIVE_INTUNE === "true")) return null;
  return mdmStats(await fetchIntune(ctx.cfg, { tenant_id: tenant, client_id: client }, secret), ctx, f);
}

async function jamf(ctx: Ctx, f: Finding) {
  const e = ctx.env;
  if (!need(e, "LIVE_JAMF_URL", "LIVE_JAMF_CLIENT_ID", "LIVE_JAMF_CLIENT_SECRET")) return null;
  const devices = await fetchJamf(ctx.cfg, { base_url: e.LIVE_JAMF_URL, client_id: e.LIVE_JAMF_CLIENT_ID }, e.LIVE_JAMF_CLIENT_SECRET!);
  if (devices.length && devices.every((d) => !d.management_id)) f.note("no management IDs came back: the API role lacks read access to them, so lock and wipe through Jamf won't work");
  return mdmStats(devices, ctx, f);
}

// ---- Alerting and SIEM -----------------------------------------------------------------------

function fakeDeps(cfg: Config, secret: string) {
  return { cfg, sealer: { open: () => Buffer.from(secret) } } as unknown as Deps;
}
const testAlert = () => ({
  id: `nexus-live-check-${randomUUID()}`,
  title: "[TEST] Votal Nexus live check: please ignore (resolves itself)",
  severity: "low" as const,
  rule_name: "Live check",
  subject: "connectivity test",
  count: 1,
  first_seen_at: new Date(),
});

async function oncall(ctx: Ctx, f: Finding, kind: "pagerduty" | "opsgenie") {
  const e = ctx.env;
  const key = kind === "pagerduty" ? e.LIVE_PAGERDUTY_ROUTING_KEY : e.LIVE_OPSGENIE_API_KEY;
  if (!key) return null;
  if (!ctx.opts.page) throw new Warn("configured, but not run: pass --page to trigger and resolve one test incident");
  const alert = testAlert();
  const i = { id: "live-check", kind, name: kind, secret: Buffer.alloc(0), region: (e.LIVE_OPSGENIE_REGION === "eu" ? "eu" : "us") as "us" | "eu", min_severity: "low" as const };
  const deps = fakeDeps(ctx.cfg, key);
  const t0 = Date.now();
  await page(deps, i, alert, "trigger", `${ctx.cfg.publicUrl}/alerts`);
  const triggered = Date.now() - t0;
  // Opsgenie creates alerts asynchronously: closing at once can race the create.
  if (kind === "opsgenie") await new Promise((r) => setTimeout(r, 3000));
  await page(deps, i, alert, "acknowledge", "");
  await page(deps, i, alert, "resolve", "");
  f.note(`triggered, acknowledged and resolved a test ${kind === "pagerduty" ? "incident" : "alert"} (check it arrived and closed)`);
  return { trigger_ms: triggered };
}

async function events(ctx: Ctx, f: Finding, kind: "sentinel" | "s3") {
  const e = ctx.env;
  const configured = kind === "sentinel" ? need(e, "LIVE_SENTINEL_ENDPOINT", "LIVE_SENTINEL_DCR_ID", "LIVE_SENTINEL_STREAM", "LIVE_SENTINEL_TENANT_ID", "LIVE_SENTINEL_CLIENT_ID", "LIVE_SENTINEL_CLIENT_SECRET") : need(e, "LIVE_S3_URL", "LIVE_S3_ACCESS_KEY_ID", "LIVE_S3_SECRET_ACCESS_KEY");
  if (!configured) return null;
  if (!ctx.opts.sendEvents) throw new Warn("configured, but not run: pass --send-events to deliver one test event");
  const event = { id: randomUUID(), type: "nexus.live_check", time: new Date(), body: { type: "nexus.live_check", message: "Votal Nexus live check test event", time: new Date().toISOString() } };
  const r =
    kind === "sentinel"
      ? await sendEvents("sentinel", e.LIVE_SENTINEL_ENDPOINT!, e.LIVE_SENTINEL_CLIENT_SECRET!, { tenant_id: e.LIVE_SENTINEL_TENANT_ID!, client_id: e.LIVE_SENTINEL_CLIENT_ID!, dcr_id: e.LIVE_SENTINEL_DCR_ID!, stream: e.LIVE_SENTINEL_STREAM! }, [event], { entraLoginBase: ctx.cfg.entraLoginBase, test: true })
      : await sendEvents("s3", e.LIVE_S3_URL!, e.LIVE_S3_SECRET_ACCESS_KEY!, { access_key_id: e.LIVE_S3_ACCESS_KEY_ID!, region: e.LIVE_S3_REGION ?? "", prefix: e.LIVE_S3_PREFIX ?? "" }, [event], { entraLoginBase: ctx.cfg.entraLoginBase, test: true });
  if (r.error) throw new Error(r.error);
  if (kind === "sentinel") f.note("delivered; the row shows up in the workspace table after a few minutes (Azure ingestion delay)");
  return { delivered: r.delivered, http_status: r.status };
}

// ---- Runner ----------------------------------------------------------------------------------

export const CHECKS: { name: string; run: (ctx: Ctx, f: Finding) => Promise<Record<string, unknown> | null> }[] = [
  { name: "entra_directory", run: entraDirectory },
  { name: "google_directory", run: googleDirectory },
  { name: "ldap_directory", run: ldapDirectory },
  { name: "oidc_discovery", run: oidc },
  { name: "saml_metadata", run: saml },
  { name: "intune", run: intune },
  { name: "jamf", run: jamf },
  { name: "pagerduty", run: (c, f) => oncall(c, f, "pagerduty") },
  { name: "opsgenie", run: (c, f) => oncall(c, f, "opsgenie") },
  { name: "sentinel", run: (c, f) => events(c, f, "sentinel") },
  { name: "s3", run: (c, f) => events(c, f, "s3") },
];

/** Makes a report safe to share: no configured secret, email, GUID or DN survives. */
export function redactor(env: Env) {
  const salt = randomBytes(8);
  const h = (s: string) => createHash("sha256").update(salt).update(s.toLowerCase()).digest("hex").slice(0, 8);
  const secrets = Object.entries(env)
    .filter(([k, v]) => k.startsWith("LIVE_") && /SECRET|PASSWORD|KEY$|KEY_ID$/.test(k) && v && v.length >= 6)
    .map(([, v]) => v!);
  return (s: string) => {
    let out = s;
    for (const v of secrets) out = out.split(v).join("<secret>");
    return out
      .replace(/[^\s@"'<>(),;:]+@[^\s@"'<>(),;:]+\.[A-Za-z]{2,}/g, (m) => `<email:${h(m)}>`)
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, (m) => `<id:${h(m)}>`)
      .replace(/\b(?:CN|OU|DC)=[^,;"]+(?:,\s*(?:CN|OU|DC|O|L|ST|C)=[^,;"]+)*/gi, (m) => `<dn:${h(m)}>`);
  };
}

export async function runLiveCheck(env: Env, cfg: Config, opts: Options, log: (line: string) => void = () => {}): Promise<Report> {
  const ctx: Ctx = { env, cfg, opts, directoryEmails: new Set() };
  const redact = redactor(env);
  const checks: CheckResult[] = [];
  for (const c of CHECKS) {
    if (opts.only && !opts.only.includes(c.name)) continue;
    const f = new Finding();
    const t0 = Date.now();
    let result: CheckResult;
    try {
      const stats = await c.run(ctx, f);
      result = stats === null ? { check: c.name, status: "skipped", ms: 0, stats: {}, findings: ["not configured"] } : { check: c.name, status: f.list.length ? "warn" : "ok", ms: Date.now() - t0, stats, findings: f.list };
    } catch (e) {
      const warn = e instanceof Warn;
      const message = e instanceof ZodError ? `invalid settings: ${e.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}` : (e as Error).message || String(e);
      result = { check: c.name, status: warn ? "skipped" : "fail", ms: Date.now() - t0, stats: {}, findings: f.list, ...(warn ? {} : { error: message }) };
      if (warn) result.findings.push((e as Error).message);
    }
    // Stats hold only counts and domains; findings and errors can quote vendor messages, so redact everything.
    const safe = JSON.parse(redact(JSON.stringify(result))) as CheckResult;
    checks.push(safe);
    if (safe.status !== "skipped" || opts.only) log(`${safe.status.toUpperCase().padEnd(7)} ${safe.check}${safe.error ? `: ${safe.error}` : ""}${safe.findings.length && safe.status !== "skipped" ? `\n${safe.findings.map((x) => `          - ${x}`).join("\n")}` : ""}`);
  }
  const summary = { ok: 0, warn: 0, fail: 0, skipped: 0 };
  for (const c of checks) summary[c.status]++;
  return { tool: "nexus-live-check", version: 1, ran_at: new Date().toISOString(), node: process.version, summary, checks };
}

import { Client, type Entry, EqualityFilter, InvalidCredentialsError } from "ldapts";

/**
 * Reads people and groups from Active Directory or any LDAP directory, for
 * Votal Nexus directory sync. Used by the API (a direct LDAPS connection) and
 * by the `nexus` CLI running on-prem (pushing to Nexus over SCIM), so both
 * map the directory the same way. Read-only, except for a user bind that
 * checks a password (delegated authentication).
 */

export type Preset = "active_directory" | "openldap" | "custom";

export type LdapConfig = {
  preset: Preset;
  /** ldaps://host:636, or ldap://host:389 with start_tls. */
  url: string;
  start_tls?: boolean;
  /** PEM of the CA that signed the directory's certificate, when it isn't publicly trusted. */
  ca_cert?: string;
  bind_dn: string;
  base_dn: string;
  user_base_dn?: string;
  group_base_dn?: string;
  user_search_filter?: string;
  group_search_filter?: string;
  /** Matches people who are disabled (besides AD's userAccountControl flag). */
  disabled_filter?: string;
  attributes?: Partial<Attributes>;
};

export type Attributes = { id: string; email: string; fallback_email: string; given_name: string; family_name: string; title: string; department: string; member: string; group_name: string; group_description: string };

export type DirectoryUser = { external_id: string; dn: string; email: string; given_name: string; family_name: string; title: string; department: string; active: boolean };
export type DirectoryGroup = { external_id: string; dn: string; name: string; description: string; member_ids: string[] };

const PRESETS: Record<Preset, { user_search_filter: string; group_search_filter: string; attributes: Attributes }> = {
  active_directory: {
    user_search_filter: "(&(objectCategory=person)(objectClass=user))",
    group_search_filter: "(objectClass=group)",
    attributes: { id: "objectGUID", email: "mail", fallback_email: "userPrincipalName", given_name: "givenName", family_name: "sn", title: "title", department: "department", member: "member", group_name: "cn", group_description: "description" },
  },
  openldap: {
    user_search_filter: "(objectClass=inetOrgPerson)",
    group_search_filter: "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))",
    attributes: { id: "entryUUID", email: "mail", fallback_email: "", given_name: "givenName", family_name: "sn", title: "title", department: "departmentNumber", member: "member", group_name: "cn", group_description: "description" },
  },
  custom: {
    user_search_filter: "(objectClass=person)",
    group_search_filter: "(objectClass=groupOfNames)",
    attributes: { id: "entryUUID", email: "mail", fallback_email: "", given_name: "givenName", family_name: "sn", title: "title", department: "department", member: "member", group_name: "cn", group_description: "description" },
  },
};

export class DirectoryError extends Error {
  constructor(
    message: string,
    /** Configuration or credentials: retrying won't help. */
    readonly permanent: boolean,
  ) {
    super(message);
  }
}

export function resolved(cfg: LdapConfig) {
  const p = PRESETS[cfg.preset];
  return {
    userFilter: cfg.user_search_filter || p.user_search_filter,
    groupFilter: cfg.group_search_filter || p.group_search_filter,
    attrs: { ...p.attributes, ...Object.fromEntries(Object.entries(cfg.attributes ?? {}).filter(([, v]) => v)) } as Attributes,
    userBase: cfg.user_base_dn || cfg.base_dn,
    groupBase: cfg.group_base_dn || cfg.base_dn,
  };
}

/** AD's objectGUID is little-endian for its first three parts; shown as the usual GUID string. */
export function guidToString(b: Buffer) {
  if (b.length !== 16) return b.toString("hex");
  const h = (i: number, n: number, rev: boolean) => {
    const part = Buffer.from(b.subarray(i, i + n));
    return (rev ? part.reverse() : part).toString("hex");
  };
  return `${h(0, 4, true)}-${h(4, 2, true)}-${h(6, 2, true)}-${h(8, 2, false)}-${h(10, 6, false)}`;
}

const first = (v: Entry[string] | undefined): string => {
  if (v === undefined) return "";
  const x = Array.isArray(v) ? v[0] : v;
  return x === undefined ? "" : Buffer.isBuffer(x) ? x.toString("utf8") : String(x);
};
const all = (v: Entry[string] | undefined): string[] => (v === undefined ? [] : (Array.isArray(v) ? v : [v]).map((x) => (Buffer.isBuffer(x) ? x.toString("utf8") : String(x))));
const normDn = (dn: string) => dn.toLowerCase().replace(/\s*,\s*/g, ",");

/** AD's userAccountControl: 0x2 is ACCOUNTDISABLE. */
export const adDisabled = (uac: string) => uac !== "" && (Number(uac) & 2) === 2;

export type ConnectOptions = { timeoutMs?: number; checkHost?: (host: string) => Promise<void> };

async function connect(cfg: LdapConfig, o: ConnectOptions) {
  let url: URL;
  try {
    url = new URL(cfg.url);
  } catch {
    throw new DirectoryError("The directory URL isn't valid (use ldaps://host:636)", true);
  }
  if (url.protocol !== "ldaps:" && url.protocol !== "ldap:") throw new DirectoryError("The directory URL must start with ldaps:// or ldap://", true);
  if (url.protocol === "ldap:" && !cfg.start_tls) throw new DirectoryError("Plain ldap:// would send the password unencrypted: use ldaps:// or turn on StartTLS", true);
  await o.checkHost?.(url.hostname);
  const tlsOptions = { ...(cfg.ca_cert ? { ca: [cfg.ca_cert] } : {}), servername: url.hostname, minVersion: "TLSv1.2" as const };
  // TLS options on the client make it speak TLS from the first byte: only for ldaps://. StartTLS gets them at upgrade.
  const client = new Client({ url: cfg.url, timeout: o.timeoutMs ?? 30_000, connectTimeout: 10_000, ...(url.protocol === "ldaps:" ? { tlsOptions } : {}), strictDN: false });
  if (cfg.start_tls && url.protocol === "ldap:") {
    try {
      await client.startTLS(tlsOptions);
    } catch (e) {
      throw new DirectoryError(`StartTLS failed: ${(e as Error).message}`, true);
    }
  }
  return client;
}

async function bind(client: Client, dn: string, password: string, what: string) {
  try {
    await client.bind(dn, password);
  } catch (e) {
    if (e instanceof InvalidCredentialsError) throw new DirectoryError(`${what}: the directory rejected the credentials`, true);
    const m = (e as Error).message;
    const permanent = /certificate|self.signed|CERT_|hostname|ENOTFOUND/i.test(m);
    throw new DirectoryError(`${what}: ${m}`, permanent);
  }
}

async function searchAll(client: Client, base: string, filter: string, attributes: string[], buffers: string[]) {
  try {
    const r = await client.search(base, { scope: "sub", filter, attributes, explicitBufferAttributes: buffers, paged: { pageSize: 500 }, sizeLimit: 0 });
    return r.searchEntries;
  } catch (e) {
    throw new DirectoryError(`Searching ${base} with ${filter}: ${(e as Error).message}`, /No Such Object|invalid|Bad search filter/i.test((e as Error).message));
  }
}

function idOf(e: Entry, attr: string): string {
  const v = e[attr];
  const x = Array.isArray(v) ? v[0] : v;
  if (Buffer.isBuffer(x)) return attr.toLowerCase() === "objectguid" ? guidToString(x) : x.toString("hex");
  return x === undefined ? "" : String(x);
}

/** Tests the connection and the service account, and counts what it can see. */
export async function testDirectory(cfg: LdapConfig, password: string, o: ConnectOptions = {}) {
  const d = await readDirectory(cfg, password, { groups: true }, o);
  return { users: d.users.length, active: d.users.filter((u) => u.active).length, groups: d.groups.length, sample: d.users.slice(0, 5).map((u) => u.email) };
}

/** Everyone the filters select (active and disabled), and groups with members expanded through nested groups. */
export async function readDirectory(cfg: LdapConfig, password: string, opts: { groups: boolean }, o: ConnectOptions = {}): Promise<{ users: DirectoryUser[]; groups: DirectoryGroup[] }> {
  const r = resolved(cfg);
  const a = r.attrs;
  const client = await connect(cfg, o);
  try {
    await bind(client, cfg.bind_dn, password, "Signing in with the service account");
    const isAd = cfg.preset === "active_directory";
    const userAttrs = [a.id, a.email, a.fallback_email, a.given_name, a.family_name, a.title, a.department, ...(isAd ? ["userAccountControl"] : [])].filter(Boolean);
    const buffers = a.id.toLowerCase() === "objectguid" ? [a.id] : [];
    const entries = await searchAll(client, r.userBase, r.userFilter, userAttrs, buffers);
    const disabled = new Set<string>();
    if (cfg.disabled_filter) {
      for (const e of await searchAll(client, r.userBase, `(&${r.userFilter}${cfg.disabled_filter})`, ["dn"], [])) disabled.add(normDn(e.dn));
    }
    const users: DirectoryUser[] = [];
    for (const e of entries) {
      const external_id = idOf(e, a.id);
      const email = (first(e[a.email]) || (a.fallback_email ? first(e[a.fallback_email]) : "")).trim().toLowerCase();
      if (!external_id || !email.includes("@")) continue; // service accounts and the like
      const active = !disabled.has(normDn(e.dn)) && !(isAd && adDisabled(first(e.userAccountControl)));
      users.push({ external_id, dn: e.dn, email, given_name: first(e[a.given_name]), family_name: first(e[a.family_name]), title: first(e[a.title]), department: first(e[a.department]), active });
    }
    const groups: DirectoryGroup[] = [];
    if (opts.groups) {
      const gEntries = await searchAll(client, r.groupBase, r.groupFilter, [a.id, a.group_name, a.group_description, a.member, "uniqueMember"], buffers);
      const userByDn = new Map(users.map((u) => [normDn(u.dn), u.external_id]));
      const groupByDn = new Map(gEntries.map((g) => [normDn(g.dn), g]));
      const members = (g: Entry) => [...all(g[a.member]), ...all(g.uniqueMember)].map(normDn);
      // Nested groups: a member that is a group contributes its members (cycles are ignored).
      const expand = (dn: string, seen: Set<string>): string[] => {
        if (seen.has(dn)) return [];
        seen.add(dn);
        const g = groupByDn.get(dn);
        if (!g) return [];
        return members(g).flatMap((m) => (userByDn.has(m) ? [userByDn.get(m)!] : groupByDn.has(m) ? expand(m, seen) : []));
      };
      for (const g of gEntries) {
        const external_id = idOf(g, a.id);
        if (!external_id) continue;
        groups.push({ external_id, dn: g.dn, name: (first(g[a.group_name]) || g.dn).slice(0, 100), description: first(g[a.group_description]).slice(0, 500), member_ids: [...new Set(expand(normDn(g.dn), new Set()))] });
      }
    }
    return { users, groups };
  } finally {
    await client.unbind().catch(() => {});
  }
}

/**
 * Delegated authentication: checks a person's password by binding as them.
 * Finds their entry by the directory's ID (the service account searches),
 * then binds with their DN. Returns false for a wrong password.
 */
export async function verifyPassword(cfg: LdapConfig, servicePassword: string, externalId: string, password: string, o: ConnectOptions = {}): Promise<boolean> {
  if (!password) return false; // an empty password would be an anonymous bind, which "succeeds"
  const r = resolved(cfg);
  const client = await connect(cfg, o);
  try {
    await bind(client, cfg.bind_dn, servicePassword, "Signing in with the service account");
    let filter: string;
    if (r.attrs.id.toLowerCase() === "objectguid") {
      const hex = externalId.replace(/-/g, "");
      const b = Buffer.from(hex, "hex");
      const le = Buffer.concat([Buffer.from(b.subarray(0, 4)).reverse(), Buffer.from(b.subarray(4, 6)).reverse(), Buffer.from(b.subarray(6, 8)).reverse(), b.subarray(8)]);
      filter = `(&${r.userFilter}(objectGUID=${[...le].map((x) => `\\${x.toString(16).padStart(2, "0")}`).join("")}))`;
    } else {
      filter = `(&${r.userFilter}${new EqualityFilter({ attribute: r.attrs.id, value: externalId }).toString()})`;
    }
    const found = await searchAll(client, r.userBase, filter, ["dn"], []);
    if (found.length !== 1) return false;
    const userClient = await connect(cfg, o);
    try {
      await userClient.bind(found[0]!.dn, password);
      return true;
    } catch (e) {
      if (e instanceof InvalidCredentialsError) return false;
      throw new DirectoryError(`Checking the password: ${(e as Error).message}`, false);
    } finally {
      await userClient.unbind().catch(() => {});
    }
  } finally {
    await client.unbind().catch(() => {});
  }
}

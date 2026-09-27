import { createHash, timingSafeEqual } from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import { sql } from "kysely";
import type { Deps } from "../context.js";
import { audit } from "../audit/record.js";
import { RateLimiter } from "../auth/ratelimit.js";
import { verifyPassword } from "../auth/passwords.js";
import { asBool, asInt, asString, type Element, enumerated, int, octets, readElement, seq } from "./ber.js";

/**
 * Nexus as an LDAP directory (LDAPv3, read-only) for what can't use SAML or OIDC: legacy apps,
 * NAS boxes, printers. Per organization:
 *
 *   o=<org>,dc=nexus
 *     ou=users    uid=<email>      inetOrgPerson: active people (mail, cn, givenName, sn, title, memberOf)
 *     ou=groups   cn=<group name>  groupOfNames (member)
 *     ou=services cn=<name>        service accounts apps bind as (never listed)
 *
 * Apps bind as a service account to search, then bind as the person with their Nexus password
 * to check it. Anonymous binds see only the root entry. A person bound as themselves sees only
 * their own entry and their groups. Binds are rate limited and audited.
 */

export const BASE = "dc=nexus";
const RC = { success: 0, operationsError: 1, protocolError: 2, sizeLimitExceeded: 4, authMethodNotSupported: 7, noSuchObject: 32, invalidCredentials: 49, insufficientAccessRights: 50, unwillingToPerform: 53 } as const;
const MAX_ENTRIES = 5000;
const IDLE_MS = 5 * 60_000;

// ---- Distinguished names (RFC 4514) ------------------------------------------------------------------

export type Rdn = [attr: string, value: string];

/** Parses a DN into its RDNs (attribute names lowercased), handling escapes. Multi-valued RDNs aren't supported. */
export function parseDn(dn: string): Rdn[] | null {
  const rdns: Rdn[] = [];
  let i = 0;
  const s = dn.trim();
  if (!s) return [];
  while (i < s.length) {
    const eq = s.indexOf("=", i);
    if (eq < 0) return null;
    const attr = s.slice(i, eq).trim().toLowerCase();
    let value = "";
    i = eq + 1;
    while (i < s.length && s[i] === " ") i++;
    for (; i < s.length; i++) {
      const ch = s[i]!;
      if (ch === "\\") {
        const hex = s.slice(i + 1, i + 3);
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          value += String.fromCharCode(parseInt(hex, 16));
          i += 2;
        } else {
          value += s[i + 1] ?? "";
          i++;
        }
      } else if (ch === "," || ch === ";") break;
      else if (ch === "+") return null;
      else value += ch;
    }
    rdns.push([attr, value.trim()]);
    i++; // the comma
  }
  return rdns;
}

/** Escapes a value for use in a DN. */
export const escapeDn = (v: string) => v.replace(/([,+"\\<>;=#])/g, "\\$1").replace(/^ /, "\\ ").replace(/ $/, "\\ ");

const normDn = (dn: string) => (parseDn(dn) ?? []).map(([a, v]) => `${a}=${v.toLowerCase()}`).join(",");

// ---- The directory --------------------------------------------------------------------------------------

/** Attributes by lowercased name (for matching), each with its proper spelling (for answers). */
type Entry = { dn: string; attrs: Map<string, string[]>; names: Map<string, string> };
type Who = { kind: "anonymous" } | { kind: "service"; orgId: string; slug: string; name: string } | { kind: "user"; orgId: string; slug: string; userId: string; dn: string };

function entry(dn: string, attrs: Record<string, string | string[] | null | undefined>): Entry {
  const m = new Map<string, string[]>();
  const names = new Map<string, string>();
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === "") continue;
    m.set(k.toLowerCase(), Array.isArray(v) ? v : [v]);
    names.set(k.toLowerCase(), k);
  }
  return { dn, attrs: m, names };
}

const orgDn = (slug: string) => `o=${escapeDn(slug)},${BASE}`;
const userDn = (slug: string, email: string) => `uid=${escapeDn(email.toLowerCase())},ou=users,${orgDn(slug)}`;
const groupDn = (slug: string, name: string) => `cn=${escapeDn(name)},ou=groups,${orgDn(slug)}`;

/** Everything under o=<org>,dc=nexus, as directory entries. */
async function loadDirectory(deps: Deps, orgId: string, slug: string): Promise<Entry[]> {
  return deps.db.tenant(orgId, async (tx) => {
    const org = await tx.selectFrom("organizations").select("name").where("id", "=", orgId).executeTakeFirstOrThrow();
    const users = await tx.selectFrom("users").select(["id", "email", "given_name", "family_name", "title", "department"]).where("status", "=", "active").orderBy("email").execute();
    const groups = await tx.selectFrom("groups").select(["id", "name", "description"]).orderBy("name").execute();
    const members = await tx.selectFrom("group_members").innerJoin("users", "users.id", "group_members.user_id").select(["group_members.group_id", "users.email"]).where("users.status", "=", "active").execute();
    const groupNames = new Map(groups.map((g) => [g.id, g.name]));
    const byUser = new Map<string, string[]>();
    const byGroup = new Map<string, string[]>();
    for (const m of members) {
      byGroup.set(m.group_id, [...(byGroup.get(m.group_id) ?? []), userDn(slug, m.email)]);
      byUser.set(m.email, [...(byUser.get(m.email) ?? []), groupDn(slug, groupNames.get(m.group_id)!)]);
    }
    const o = orgDn(slug);
    return [
      entry(o, { objectClass: ["top", "organization"], o: slug, description: org.name }),
      entry(`ou=users,${o}`, { objectClass: ["top", "organizationalUnit"], ou: "users" }),
      entry(`ou=groups,${o}`, { objectClass: ["top", "organizationalUnit"], ou: "groups" }),
      ...users.map((u) => {
        const name = `${u.given_name} ${u.family_name}`.trim() || u.email;
        return entry(userDn(slug, u.email), {
          objectClass: ["top", "person", "organizationalPerson", "inetOrgPerson"],
          uid: u.email.toLowerCase(),
          mail: u.email,
          cn: name,
          displayName: name,
          givenName: u.given_name,
          sn: u.family_name || name,
          title: u.title,
          departmentNumber: u.department,
          memberOf: byUser.get(u.email) ?? [],
          entryUUID: u.id,
        });
      }),
      ...groups.map((g) => entry(groupDn(slug, g.name), { objectClass: ["top", "groupOfNames"], cn: g.name, description: g.description, member: byGroup.get(g.id) ?? [], entryUUID: g.id })),
    ];
  });
}

// ---- Filters (RFC 4511 §4.5.1.7) ---------------------------------------------------------------------------

const lc = (s: string) => s.toLowerCase();
function values(e: Entry, attr: string) {
  return e.attrs.get(lc(attr)) ?? [];
}

/** Evaluates a BER-encoded filter against an entry. Unsupported filters (extensible match) don't match. */
export function matches(f: Element, e: Entry): boolean {
  const kids = f.children ?? [];
  switch (f.tag) {
    case 0xa0:
      return kids.every((k) => matches(k, e));
    case 0xa1:
      return kids.some((k) => matches(k, e));
    case 0xa2:
      return !matches(kids[0]!, e);
    case 0xa3: // equality
    case 0xa8: {
      // approx: as equality
      const want = lc(asString(kids[1]));
      return values(e, asString(kids[0])).some((v) => lc(v) === want);
    }
    case 0xa4: {
      const parts = kids[1]?.children ?? [];
      return values(e, asString(kids[0])).some((raw) => {
        const v = lc(raw);
        let pos = 0;
        for (const p of parts) {
          const s = lc(asString(p));
          if (p.tag === 0x80) {
            if (!v.startsWith(s)) return false;
            pos = s.length;
          } else if (p.tag === 0x81) {
            const at = v.indexOf(s, pos);
            if (at < 0) return false;
            pos = at + s.length;
          } else if (p.tag === 0x82) {
            if (!v.endsWith(s) || v.length - s.length < pos) return false;
          }
        }
        return true;
      });
    }
    case 0xa5:
      return values(e, asString(kids[0])).some((v) => lc(v) >= lc(asString(kids[1])));
    case 0xa6:
      return values(e, asString(kids[0])).some((v) => lc(v) <= lc(asString(kids[1])));
    case 0x87: {
      const attr = lc(asString(f));
      return attr === "objectclass" || values(e, attr).length > 0;
    }
    default:
      return false;
  }
}

// ---- The protocol ----------------------------------------------------------------------------------------

const ldapResult = (tag: number, code: number, message = "", matchedDn = "") => seq(tag, [enumerated(code), octets(matchedDn), octets(message)]);
const envelope = (id: number, op: Buffer) => seq(0x30, [int(id), op]);

function searchEntry(e: Entry, want: Set<string>, typesOnly: boolean) {
  const all = want.size === 0 || want.has("*");
  const attrs: Buffer[] = [];
  for (const [name, vals] of e.attrs) {
    if (!all && !want.has(name)) continue;
    attrs.push(seq(0x30, [octets(e.names.get(name) ?? name), seq(0x31, typesOnly ? [] : vals.map((v) => octets(v)))]));
  }
  return seq(0x64, [octets(e.dn), seq(0x30, attrs)]);
}

type Conn = { who: Who; cache?: { at: number; entries: Entry[] } };

/** Resolves an organization from a DN under dc=nexus: o=<slug>,dc=nexus. */
function slugOf(dn: string): string | null {
  const rdns = parseDn(dn);
  if (!rdns || rdns.length < 2) return null;
  const [dcAttr, dcVal] = rdns.at(-1)!;
  const [oAttr, oVal] = rdns.at(-2)!;
  return dcAttr === "dc" && lc(dcVal) === "nexus" && oAttr === "o" ? lc(oVal) : null;
}

const secretMatches = (given: string, storedHex: string) => {
  const a = createHash("sha256").update(given).digest();
  const b = Buffer.from(storedHex, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
};

export type LdapOptions = { port: number; host?: string; tls?: { cert: string; key: string } };

export function startLdapServer(deps: Deps, opts: LdapOptions) {
  const perUser = new RateLimiter(10, 5 * 60_000, "ldap-user");
  const perIp = new RateLimiter(60, 5 * 60_000, "ldap-ip");
  const orgBySlug = async (slug: string) =>
    deps.db.unscoped(async (tx) => (await sql<{ org_id: string }>`SELECT org_id FROM nexus_org_by_slug(${slug})`.execute(tx)).rows[0]?.org_id ?? null);
  const enabled = (orgId: string) =>
    deps.db.tenant(orgId, async (tx) => !!(await tx.selectFrom("directory_service_settings").select("ldap_enabled").where("ldap_enabled", "=", true).executeTakeFirst()));

  async function bind(conn: Conn, dn: string, password: string, ip: string): Promise<[number, string]> {
    if (!dn && !password) {
      conn.who = { kind: "anonymous" };
      return [RC.success, ""];
    }
    if (!password) return [RC.unwillingToPerform, "Unauthenticated binds (a name without a password) aren't allowed"];
    const slug = slugOf(dn);
    const rdns = parseDn(dn);
    if (!slug || !rdns || rdns.length !== 4) return [RC.invalidCredentials, ""];
    const orgId = await orgBySlug(slug);
    if (!orgId || !(await enabled(orgId))) return [RC.invalidCredentials, ""];
    if (!(await perIp.take(`${orgId}:${ip}`))) return [RC.unwillingToPerform, "Too many attempts; try again later"];
    const [[attr, value], [ouAttr, ou]] = rdns as [Rdn, Rdn];
    if (ouAttr !== "ou") return [RC.invalidCredentials, ""];

    if (lc(ou) === "services" && attr === "cn") {
      const ok = await deps.db.tenant(orgId, async (tx) => {
        const a = await tx.selectFrom("ldap_service_accounts").select(["id", "secret_hash"]).where("name", "=", lc(value)).where("revoked_at", "is", null).executeTakeFirst();
        if (!a || !secretMatches(password, a.secret_hash)) {
          await audit(tx, orgId, { meta: { ip, userAgent: "ldap", requestId: "" } }, { type: "ldap.bind", outcome: "failure", actor: { type: "system", id: null, display: `ldap service ${value}` }, details: { dn } });
          return false;
        }
        await sql`UPDATE ldap_service_accounts SET last_used_at = now() WHERE id = ${a.id} AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')`.execute(tx);
        return true;
      });
      if (!ok) return [RC.invalidCredentials, ""];
      conn.who = { kind: "service", orgId, slug, name: lc(value) };
      conn.cache = undefined;
      return [RC.success, ""];
    }

    if (lc(ou) === "users" && (attr === "uid" || attr === "mail")) {
      const email = lc(value);
      if (!(await perUser.take(`${orgId}:${email}`))) return [RC.unwillingToPerform, "Too many attempts for this account; try again later"];
      const u = await deps.db.tenant(orgId, (tx) => tx.selectFrom("users").select(["id", "email", "status", "password_hash"]).where(sql`lower(email)`, "=", email).executeTakeFirst());
      const ok = !!u && u.status === "active" && (await verifyPassword(u.password_hash, password));
      await deps.db.tenant(orgId, (tx) =>
        audit(tx, orgId, { meta: { ip, userAgent: "ldap", requestId: "" } }, {
          type: "ldap.bind",
          outcome: ok ? "success" : "failure",
          actor: u ? { type: "user", id: u.id, display: u.email } : { type: "system", id: null, display: email },
          details: { dn },
        }),
      );
      if (!ok || !u) return [RC.invalidCredentials, ""];
      conn.who = { kind: "user", orgId, slug, userId: u.id, dn: userDn(slug, u.email) };
      conn.cache = undefined;
      return [RC.success, ""];
    }
    return [RC.invalidCredentials, ""];
  }

  async function search(conn: Conn, req: Element, send: (b: Buffer) => void, id: number): Promise<[number, string, string]> {
    const [baseEl, scopeEl, , sizeEl, , typesEl, filter, attrsEl] = req.children ?? [];
    const base = asString(baseEl);
    const scope = asInt(scopeEl);
    const typesOnly = asBool(typesEl);
    const want = new Set((attrsEl?.children ?? []).map((a) => lc(asString(a))).filter((a) => a !== "1.1"));
    const limit = Math.min(asInt(sizeEl) || MAX_ENTRIES, MAX_ENTRIES);

    // The root entry: what clients probe before binding.
    if (base === "" && scope === 0) {
      const namingContexts = conn.who.kind === "anonymous" ? [BASE] : [orgDn(conn.who.slug)];
      const root = entry("", { objectClass: ["top"], namingContexts, supportedLDAPVersion: "3", vendorName: "Votal Nexus", supportedExtension: "1.3.6.1.4.1.4203.1.11.3" });
      if (!filter || matches(filter, root)) send(envelope(id, searchEntry(root, want, typesOnly)));
      return [RC.success, "", ""];
    }
    if (conn.who.kind === "anonymous") return [RC.insufficientAccessRights, "Bind first", ""];
    const slug = slugOf(base) ?? (lc(normDn(base)) === BASE ? conn.who.slug : null);
    if (slug !== conn.who.slug) return [RC.noSuchObject, "", ""];

    if (!conn.cache || Date.now() - conn.cache.at > 60_000) conn.cache = { at: Date.now(), entries: await loadDirectory(deps, conn.who.orgId, conn.who.slug) };
    let entries = conn.cache.entries;
    // A person sees their own entry and their groups; service accounts see everything.
    if (conn.who.kind === "user") {
      const me = normDn(conn.who.dn);
      const mine = entries.find((e) => normDn(e.dn) === me);
      const myGroups = new Set((mine?.attrs.get("memberof") ?? []).map(normDn));
      entries = entries.filter((e) => normDn(e.dn) === me || myGroups.has(normDn(e.dn)));
    }
    const nb = normDn(base === "" || lc(normDn(base)) === BASE ? orgDn(conn.who.slug) : base);
    if (!entries.some((e) => normDn(e.dn) === nb) && conn.who.kind === "service") return [RC.noSuchObject, "", orgDn(conn.who.slug)];
    const depth = (dn: string) => (parseDn(dn) ?? []).length;
    const baseDepth = depth(nb);
    const inScope = (e: Entry) => {
      const n = normDn(e.dn);
      if (scope === 0) return n === nb;
      if (!n.endsWith(nb)) return false;
      if (scope === 1) return depth(e.dn) === baseDepth + 1 && n.endsWith(`,${nb}`);
      return n === nb || n.endsWith(`,${nb}`);
    };
    let sent = 0;
    for (const e of entries) {
      if (!inScope(e) || (filter && !matches(filter, e))) continue;
      if (sent >= limit) return [RC.sizeLimitExceeded, "", ""];
      send(envelope(id, searchEntry(e, want, typesOnly)));
      sent++;
    }
    return [RC.success, "", ""];
  }

  const handle = (socket: net.Socket) => {
    const conn: Conn = { who: { kind: "anonymous" } };
    const ip = (socket.remoteAddress ?? "").replace(/^::ffff:/, "");
    let buf = Buffer.alloc(0);
    let queue: Promise<unknown> = Promise.resolve();
    socket.setTimeout(IDLE_MS, () => socket.destroy());
    socket.on("error", () => socket.destroy());
    socket.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 2 * 1024 * 1024) return socket.destroy();
      for (;;) {
        let r: ReturnType<typeof readElement>;
        try {
          r = readElement(buf);
        } catch {
          return socket.destroy();
        }
        if (!r) break;
        buf = buf.subarray(r.next);
        const msg = r.el;
        // One operation at a time per connection, in order.
        queue = queue.then(() => process(msg)).catch(() => socket.destroy());
      }
    });
    const send = (b: Buffer) => socket.writable && socket.write(b);
    const process = async (msg: Element) => {
      const [idEl, op] = msg.children ?? [];
      const id = asInt(idEl);
      if (!op) return socket.destroy();
      switch (op.tag) {
        case 0x60: {
          const [versionEl, nameEl, auth] = op.children ?? [];
          if (asInt(versionEl) !== 3) return send(envelope(id, ldapResult(0x61, RC.protocolError, "LDAPv3 only")));
          if (auth?.tag !== 0x80) return send(envelope(id, ldapResult(0x61, RC.authMethodNotSupported, "Simple binds only (over TLS)")));
          const [code, message] = await bind(conn, asString(nameEl), asString(auth), ip);
          return send(envelope(id, ldapResult(0x61, code, message)));
        }
        case 0x63: {
          const [code, message, matched] = await search(conn, op, send, id);
          return send(envelope(id, ldapResult(0x65, code, message, matched)));
        }
        case 0x42: // unbind
          return socket.end();
        case 0x50: // abandon: searches finish quickly; nothing to cancel
          return;
        case 0x77: {
          const oid = asString(op.children?.[0]);
          if (oid === "1.3.6.1.4.1.4203.1.11.3") {
            const whoami = conn.who.kind === "user" ? `dn:${conn.who.dn}` : conn.who.kind === "service" ? `dn:cn=${conn.who.name},ou=services,${orgDn(conn.who.slug)}` : "";
            return send(envelope(id, seq(0x78, [enumerated(RC.success), octets(""), octets(""), octets(whoami, 0x8b)])));
          }
          return send(envelope(id, seq(0x78, [enumerated(RC.protocolError), octets(""), octets(`Unsupported extended operation ${oid}`)])));
        }
        default: {
          // Modify, add, delete…: this directory is read-only (it follows Nexus).
          const responseTag = op.tag === 0x66 ? 0x67 : op.tag === 0x68 ? 0x69 : op.tag === 0x4a ? 0x6b : op.tag === 0x6c ? 0x6d : op.tag === 0x6e ? 0x6f : 0x65;
          return send(envelope(id, ldapResult(responseTag, RC.unwillingToPerform, "This directory is read-only: change people and groups in Nexus")));
        }
      }
    };
  };

  const sockets = new Set<net.Socket>();
  const track = (s: net.Socket) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
    handle(s);
  };
  const server = opts.tls ? tls.createServer({ cert: opts.tls.cert, key: opts.tls.key, minVersion: "TLSv1.2" }, track) : net.createServer(track);
  return new Promise<{ port: number; close: () => Promise<void> }>((resolve) => {
    server.listen(opts.port, opts.host ?? "0.0.0.0", () => {
      const port = (server.address() as net.AddressInfo).port;
      // Shutting down: stop accepting, then end connections apps left open.
      resolve({
        port,
        close: () =>
          new Promise((r) => {
            server.close(() => r());
            for (const s of sockets) s.destroy();
          }),
      });
    });
  });
}

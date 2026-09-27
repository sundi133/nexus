import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { lookup } from "node:dns/promises";
import { Agent, setGlobalDispatcher } from "undici";
import { isIP } from "node:net";

/**
 * Guard for admin-supplied URLs the server will call (SCIM endpoints,
 * webhooks, SIEM collectors): https only, and never private, loopback,
 * link-local or metadata addresses, which would let a tenant reach our own
 * network (SSRF). Checked after DNS resolution.
 */

export class UnsafeUrlError extends Error {}

/** The 16 bytes of an IPv6 address (null if it can't be parsed). */
function v6bytes(ip: string): number[] | null {
  let s = ip.toLowerCase().split("%")[0]!;
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (dotted) {
    const p = dotted[1]!.split(".").map(Number);
    s = s.slice(0, -dotted[1]!.length) + `${((p[0]! << 8) | p[1]!).toString(16)}:${((p[2]! << 8) | p[3]!).toString(16)}`;
  }
  const [head, tail] = s.split("::") as [string, string | undefined];
  const h = head ? head.split(":") : [];
  const t = tail !== undefined && tail !== "" ? tail.split(":") : [];
  const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  if (groups.length !== 8) return null;
  return groups.flatMap((g) => {
    const n = parseInt(g || "0", 16);
    return [(n >> 8) & 255, n & 255];
  });
}

function isPrivate(ip: string): boolean {
  if (ip.includes(":")) {
    const b = v6bytes(ip);
    if (!b) return true; // unparseable: refuse
    const v4 = (i: number) => `${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`;
    const zeros = (n: number) => b.slice(0, n).every((x) => x === 0);
    if (zeros(16) || (zeros(15) && b[15] === 1)) return true; // :: and ::1
    if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return true; // fe80::/10 link-local
    if (b[0] === 0xfe && (b[1]! & 0xc0) === 0xc0) return true; // fec0::/10 site-local
    if ((b[0]! & 0xfe) === 0xfc) return true; // fc00::/7 unique local
    if (b[0] === 0xff) return true; // multicast
    if (zeros(10) && b[10] === 0xff && b[11] === 0xff) return isPrivate(v4(12)); // ::ffff:a.b.c.d
    if (zeros(12)) return isPrivate(v4(12)); // ::a.b.c.d (deprecated compatible)
    if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return isPrivate(v4(12)); // 64:ff9b::/96 NAT64
    if (b[0] === 0x20 && b[1] === 0x02) return isPrivate(v4(2)); // 2002::/16 6to4
    return false;
  }
  const [a, b] = ip.split(".").map(Number) as [number, number];
  return (
    a === 10 || a === 127 || a === 0 ||
    (a === 169 && b === 254) || // link-local, cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    a >= 224 // multicast, reserved
  );
}

export async function assertSafeUrl(raw: string, opts: { allowPrivate: boolean }): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeUrlError("Not a valid URL");
  }
  if (url.username || url.password) throw new UnsafeUrlError("URLs can't contain credentials");
  if (opts.allowPrivate) {
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new UnsafeUrlError("Only http(s) URLs are allowed");
    return url;
  }
  if (url.protocol !== "https:") throw new UnsafeUrlError("The URL must use https");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addrs = isIP(host) ? [host] : (await lookup(host, { all: true }).catch(() => [])).map((a) => a.address);
  if (addrs.length === 0) throw new UnsafeUrlError(`Couldn't resolve ${host}`);
  if (addrs.some(isPrivate)) throw new UnsafeUrlError(`${host} points to a private or internal address`);
  return url;
}

export const _isPrivate = isPrivate;

/** "fetch failed" hides the reason; surface the underlying cause (DNS, refused, TLS, blocked port…). */
export function networkError(err: unknown): string {
  const e = err as Error & { cause?: { code?: string; message?: string } };
  const cause = e?.cause?.code ?? e?.cause?.message;
  return cause && e.message === "fetch failed" ? `fetch failed (${cause})` : (e?.message ?? String(err));
}

/**
 * DNS rebinding: a name can resolve to a public address when checked and a private one when
 * connected. In production every outbound HTTP connection (webhooks, SIEM, SCIM, MCP upstreams,
 * IdP discovery and keys) checks the address it actually connects to. Call once at startup.
 */
export function installOutboundGuard(allowPrivate: boolean) {
  if (allowPrivate) return;
  setGlobalDispatcher(
    new Agent({
      connect: {
        lookup: (hostname, options, callback) => {
          dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
            if (err) return callback(err, "", 0);
            const list = addresses as LookupAddress[];
            const bad = list.find((a) => isPrivate(a.address));
            if (bad) return callback(Object.assign(new Error(`${hostname} resolved to a private or internal address (${bad.address}); refusing to connect`), { code: "EPRIVATE" }), "", 0);
            if ((options as { all?: boolean }).all) return (callback as unknown as (e: null, a: LookupAddress[]) => void)(null, list);
            return callback(null, list[0]!.address, list[0]!.family);
          });
        },
      },
    }),
  );
}

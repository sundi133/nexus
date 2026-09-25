import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

/**
 * Guard for admin-supplied URLs the server will call (SCIM endpoints,
 * webhooks, SIEM collectors): https only, and never private, loopback,
 * link-local or metadata addresses, which would let a tenant reach our own
 * network (SSRF). Checked after DNS resolution.
 */

export class UnsafeUrlError extends Error {}

function isPrivate(ip: string): boolean {
  if (ip.includes(":")) {
    const v = ip.toLowerCase();
    if (v === "::1" || v === "::") return true;
    if (v.startsWith("fe80:") || v.startsWith("fc") || v.startsWith("fd")) return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v);
    return mapped ? isPrivate(mapped[1]!) : false;
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

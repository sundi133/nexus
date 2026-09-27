/**
 * The slice of ASN.1 BER that LDAP needs (RFC 4511 §5.1): definite lengths, integers,
 * octet strings, booleans, enumerations, sequences, sets and context/application tags.
 */

export type Element = { tag: number; value: Buffer; children?: Element[] };

const CONSTRUCTED = 0x20;

/** Reads one element at `offset`; null when the buffer doesn't hold a whole one yet. */
export function readElement(buf: Buffer, offset = 0): { el: Element; next: number } | null {
  if (buf.length < offset + 2) return null;
  const tag = buf[offset]!;
  let len = buf[offset + 1]!;
  let pos = offset + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error("unsupported BER length");
    if (buf.length < pos + n) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + i]!;
    pos += n;
  }
  if (len > 8 * 1024 * 1024) throw new Error("BER element too large");
  if (buf.length < pos + len) return null;
  const value = buf.subarray(pos, pos + len);
  const el: Element = { tag, value };
  if (tag & CONSTRUCTED) {
    el.children = [];
    let p = 0;
    while (p < value.length) {
      const r = readElement(value, p);
      if (!r) throw new Error("truncated BER element");
      el.children.push(r.el);
      p = r.next;
    }
  }
  return { el, next: pos + len };
}

export const asString = (e: Element | undefined) => (e ? e.value.toString("utf8") : "");
export function asInt(e: Element | undefined): number {
  if (!e || !e.value.length) return 0;
  let n = e.value[0]! & 0x80 ? -1 : 0;
  for (const b of e.value) n = n * 256 + b;
  return n;
}
export const asBool = (e: Element | undefined) => !!e && e.value.length > 0 && e.value[0] !== 0;

// ---- Writing ---------------------------------------------------------------------------------------

function lengthBytes(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export const tlv = (tag: number, value: Buffer) => Buffer.concat([Buffer.from([tag]), lengthBytes(value.length), value]);
export const seq = (tag: number, parts: Buffer[]) => tlv(tag, Buffer.concat(parts));
export const octets = (s: string | Buffer, tag = 0x04) => tlv(tag, typeof s === "string" ? Buffer.from(s, "utf8") : s);
export function int(n: number, tag = 0x02): Buffer {
  const bytes: number[] = [];
  let v = n;
  do {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  if (bytes[0]! & 0x80) bytes.unshift(0);
  return tlv(tag, Buffer.from(bytes));
}
export const enumerated = (n: number) => int(n, 0x0a);
export const bool = (b: boolean) => tlv(0x01, Buffer.from([b ? 0xff : 0]));

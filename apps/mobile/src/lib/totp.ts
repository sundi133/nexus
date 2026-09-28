import { hmac } from "@noble/hashes/hmac.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

/**
 * Authenticator codes (TOTP, RFC 6238), computed on the phone so they work with no connection.
 * Accounts come from the standard otpauth:// QR codes that Nexus and other services show.
 */

export type Algorithm = "SHA1" | "SHA256" | "SHA512";
export type OtpAccount = { id: string; issuer: string; label: string; secret: string; algorithm: Algorithm; digits: 6 | 7 | 8; period: number };

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  if (!clean || /[^A-Z2-7]/.test(clean)) throw new Error("That secret isn't valid base32 (letters A–Z and digits 2–7)");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

const HASH = { SHA1: sha1, SHA256: sha256, SHA512: sha512 };

/** HOTP (RFC 4226) for one counter value. */
export function hotp(key: Uint8Array, counter: number, digits = 6, algorithm: Algorithm = "SHA1"): string {
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const mac = hmac(HASH[algorithm], key, msg);
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/** The account's code now, and how many seconds it has left. */
export function totp(a: Pick<OtpAccount, "secret" | "algorithm" | "digits" | "period">, now = Date.now()) {
  const step = Math.floor(now / 1000 / a.period);
  return { code: hotp(base32Decode(a.secret), step, a.digits, a.algorithm), remaining: a.period - (Math.floor(now / 1000) % a.period) };
}

/** Reads an otpauth://totp/Issuer:account?secret=…&issuer=… URI. */
export function parseOtpauth(uri: string): Omit<OtpAccount, "id"> {
  let url: URL;
  try {
    url = new URL(uri.trim());
  } catch {
    throw new Error("That isn't an authenticator QR code");
  }
  if (url.protocol !== "otpauth:") throw new Error("That isn't an authenticator QR code");
  if (url.host.toLowerCase() !== "totp") throw new Error("Only time-based codes (TOTP) are supported");
  const params = url.searchParams;
  const secret = (params.get("secret") ?? "").toUpperCase().replace(/\s/g, "");
  base32Decode(secret); // throws if invalid
  const path = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
  const [pathIssuer, ...rest] = path.includes(":") ? path.split(":") : ["", path];
  const label = (rest.join(":") || path).trim();
  const algorithm = (params.get("algorithm") ?? "SHA1").toUpperCase();
  if (algorithm !== "SHA1" && algorithm !== "SHA256" && algorithm !== "SHA512") throw new Error(`Unsupported algorithm ${algorithm}`);
  const digits = Number(params.get("digits") ?? 6);
  if (digits !== 6 && digits !== 7 && digits !== 8) throw new Error(`Unsupported number of digits: ${digits}`);
  const period = Number(params.get("period") ?? 30);
  if (!Number.isInteger(period) || period < 10 || period > 300) throw new Error(`Unsupported period: ${period}`);
  return { issuer: (params.get("issuer") ?? pathIssuer ?? "").trim(), label, secret, algorithm, digits, period };
}

/** Groups a code for reading: 123 456, 1234 5678. */
export const formatCode = (code: string) => (code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : code);

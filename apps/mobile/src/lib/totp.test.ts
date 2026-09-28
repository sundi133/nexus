import { describe, expect, it } from "vitest";
import { base32Decode, formatCode, parseOtpauth, totp } from "./totp";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes: Uint8Array) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
const ascii = (s: string) => new TextEncoder().encode(s);

describe("TOTP (RFC 6238 appendix B)", () => {
  const keys = {
    SHA1: base32Encode(ascii("12345678901234567890")),
    SHA256: base32Encode(ascii("12345678901234567890123456789012")),
    SHA512: base32Encode(ascii("1234567890123456789012345678901234567890123456789012345678901234")),
  } as const;
  const vectors: [number, string, string, string][] = [
    [59, "94287082", "46119246", "90693936"],
    [1111111109, "07081804", "68084774", "25091201"],
    [1111111111, "14050471", "67062674", "99943326"],
    [1234567890, "89005924", "91819424", "93441116"],
    [2000000000, "69279037", "90698825", "38618901"],
    [20000000000, "65353130", "77737706", "47863826"],
  ];
  for (const [t, s1, s256, s512] of vectors) {
    it(`at ${t}s`, () => {
      expect(totp({ secret: keys.SHA1, algorithm: "SHA1", digits: 8, period: 30 }, t * 1000).code).toBe(s1);
      expect(totp({ secret: keys.SHA256, algorithm: "SHA256", digits: 8, period: 30 }, t * 1000).code).toBe(s256);
      expect(totp({ secret: keys.SHA512, algorithm: "SHA512", digits: 8, period: 30 }, t * 1000).code).toBe(s512);
    });
  }
  it("counts down within the period", () => {
    expect(totp({ secret: keys.SHA1, algorithm: "SHA1", digits: 6, period: 30 }, 59_000)).toEqual({ code: "287082", remaining: 1 });
  });
});

describe("otpauth URIs", () => {
  it("reads what Nexus and most services show", () => {
    expect(parseOtpauth("otpauth://totp/Votal%20Nexus:ana%40acme.com?secret=jbsw%20y3dpehpk3pxp&issuer=Votal%20Nexus")).toEqual({
      issuer: "Votal Nexus",
      label: "ana@acme.com",
      secret: "JBSWY3DPEHPK3PXP",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    });
    expect(parseOtpauth("otpauth://totp/github.com?secret=JBSWY3DPEHPK3PXP&digits=8&algorithm=sha256&period=60")).toMatchObject({ issuer: "", label: "github.com", digits: 8, algorithm: "SHA256", period: 60 });
  });
  it("refuses what it can't use", () => {
    expect(() => parseOtpauth("https://example.com")).toThrow("authenticator QR");
    expect(() => parseOtpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1")).toThrow("time-based");
    expect(() => parseOtpauth("otpauth://totp/x?secret=not-base32!")).toThrow("base32");
    expect(() => parseOtpauth("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5")).toThrow("digits");
  });
  it("decodes base32 and groups codes", () => {
    expect(Array.from(base32Decode("MZXW6==="))).toEqual([102, 111, 111]); // "foo"
    expect(formatCode("123456")).toBe("123 456");
    expect(formatCode("12345678")).toBe("1234 5678");
  });
});

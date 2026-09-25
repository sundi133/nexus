import { randomBytes, createCipheriv } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseSealKeys, Sealer } from "./seal.js";

const k1 = randomBytes(32);
const k2 = randomBytes(32);

/** The pre-rotation format: [iv][tag][body] with no header. */
function legacySeal(key: Buffer, plain: Buffer, aad: string) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(Buffer.from(aad));
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]);
}

describe("sealing with key rotation", () => {
  it("round-trips and binds to its owner", () => {
    const s = new Sealer(k1);
    const sealed = s.seal(Buffer.from("totp-seed"), "factor:1");
    expect(sealed[0]).toBe(0xa7);
    expect(sealed[1]).toBe(1);
    expect(s.open(sealed, "factor:1").toString()).toBe("totp-seed");
    expect(() => s.open(sealed, "factor:2")).toThrow();
  });

  it("reads secrets sealed before versioning", () => {
    const old = legacySeal(k1, Buffer.from("old secret"), "x");
    const s = new Sealer([{ id: 2, key: k2 }, { id: 1, key: k1 }]);
    expect(s.open(old, "x").toString()).toBe("old secret");
    expect(s.needsReseal(old, "x")).toBe(true);
  });

  it("handles legacy ciphertexts that happen to start with the marker byte", () => {
    const s = new Sealer([{ id: 2, key: k2 }, { id: 1, key: k1 }]);
    let old: Buffer;
    do old = legacySeal(k1, Buffer.from("lookalike"), "y");
    while (old[0] !== 0xa7);
    expect(s.open(old, "y").toString()).toBe("lookalike");
    expect(s.keyIdOf(old, "y")).toBe(1);
  });

  it("seals with the current key and still opens older ones", () => {
    const before = new Sealer([{ id: 1, key: k1 }]).seal(Buffer.from("a"), "z");
    const rotated = new Sealer([{ id: 2, key: k2 }, { id: 1, key: k1 }]);
    const after = rotated.seal(Buffer.from("b"), "z");
    expect(after[1]).toBe(2);
    expect(rotated.open(before, "z").toString()).toBe("a");
    expect(rotated.needsReseal(before, "z")).toBe(true);
    expect(rotated.needsReseal(after, "z")).toBe(false);
    // Once key 1 is gone, what it sealed can't be opened.
    expect(() => new Sealer([{ id: 2, key: k2 }]).open(before, "z")).toThrow();
  });

  it("parses the key list", () => {
    const keys = parseSealKeys(` 2:${k2.toString("base64")}, 1:${k1.toString("base64")} `);
    expect(keys.map((k) => k.id)).toEqual([2, 1]);
    expect(() => parseSealKeys("0:abc")).toThrow("1–255");
    expect(() => parseSealKeys(`3:${randomBytes(16).toString("base64")}`)).toThrow("32 bytes");
  });
});

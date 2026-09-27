import { describe, expect, it } from "vitest";
import { asBool, asInt, asString, bool, enumerated, int, octets, readElement, seq } from "./ber.js";

describe("BER", () => {
  it("round-trips the shapes LDAP uses", () => {
    const msg = seq(0x30, [int(7), seq(0x60, [int(3), octets("uid=pat,ou=users,o=acme,dc=nexus"), octets("s3cret", 0x80)]), bool(true), enumerated(49)]);
    const r = readElement(msg)!;
    expect(r.next).toBe(msg.length);
    const [id, bind, b, e] = r.el.children!;
    expect(asInt(id)).toBe(7);
    expect(bind!.tag).toBe(0x60);
    expect(asString(bind!.children![1])).toBe("uid=pat,ou=users,o=acme,dc=nexus");
    expect(asString(bind!.children![2])).toBe("s3cret");
    expect(asBool(b)).toBe(true);
    expect(asInt(e)).toBe(49);
  });

  it("uses long-form lengths and positive integers correctly", () => {
    const big = octets("x".repeat(300));
    expect(big.subarray(0, 4)).toEqual(Buffer.from([0x04, 0x82, 0x01, 0x2c]));
    expect(asString(readElement(big)!.el)).toHaveLength(300);
    for (const n of [0, 127, 128, 255, 256, 65535, 2147483647]) expect(asInt(readElement(int(n))!.el)).toBe(n);
    expect(int(128)).toEqual(Buffer.from([0x02, 0x02, 0x00, 0x80])); // no sign bit misread
  });

  it("waits for a whole message and refuses absurd ones", () => {
    const msg = seq(0x30, [int(1), octets("hello")]);
    expect(readElement(msg.subarray(0, msg.length - 1))).toBeNull();
    expect(() => readElement(Buffer.from([0x04, 0x84, 0x7f, 0xff, 0xff, 0xff]))).toThrow("too large");
  });
});

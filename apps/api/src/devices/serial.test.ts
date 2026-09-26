import { describe, expect, it } from "vitest";
import { usableSerial } from "./serial.js";

describe("usableSerial", () => {
  it("keeps real serials, lowercased", () => {
    expect(usableSerial(" C02XK1ABJG5H ")).toBe("c02xk1abjg5h");
    expect(usableSerial("VMware-56 4d 1a 2b")).toBe("vmware-56 4d 1a 2b");
    expect(usableSerial("PF3ABCDE")).toBe("pf3abcde");
  });
  it("refuses placeholders every machine of a model shares", () => {
    for (const s of ["", "  ", "0", "N/A", "To Be Filled By O.E.M.", "TO BE FILLED BY O.E.M", "System Serial Number", "Default string", "Not Specified", "None", "0000000000", "XXXXXXXX", "0000-0000-0000-0000", "123456789", "Chassis Serial Number", null, undefined])
      expect(usableSerial(s), String(s)).toBeNull();
  });
});

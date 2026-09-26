import { describe, expect, it } from "vitest";
import { hhmm, inWindow, isTimeZone, localMinutes, nextLocalTime } from "./schedule.js";

describe("quiet hours and digest times", () => {
  it("reads the local clock in the user's zone", () => {
    const t = new Date("2026-09-24T21:30:00Z");
    expect(localMinutes(t, "UTC")).toBe(21 * 60 + 30);
    expect(hhmm(t, "America/Los_Angeles")).toBe("14:30");
    expect(hhmm(t, "Asia/Kolkata")).toBe("03:00");
    expect(isTimeZone("Europe/Berlin")).toBe(true);
    expect(isTimeZone("Mars/Olympus")).toBe(false);
  });

  it("handles windows that wrap past midnight", () => {
    const at = (iso: string) => new Date(iso);
    expect(inWindow(at("2026-09-24T23:00:00Z"), "22:00", "07:00", "UTC")).toBe(true);
    expect(inWindow(at("2026-09-24T06:59:00Z"), "22:00", "07:00", "UTC")).toBe(true);
    expect(inWindow(at("2026-09-24T07:00:00Z"), "22:00", "07:00", "UTC")).toBe(false);
    expect(inWindow(at("2026-09-24T12:30:00Z"), "12:00", "13:00", "UTC")).toBe(true);
    expect(inWindow(at("2026-09-24T12:30:00Z"), "09:00", "09:00", "UTC")).toBe(false);
    expect(inWindow(at("2026-09-25T05:00:00Z"), "22:00", "07:00", "America/New_York")).toBe(true); // 01:00 in New York
  });

  it("finds the next local time, today or tomorrow", () => {
    expect(nextLocalTime(new Date("2026-09-24T05:00:00Z"), "07:00", "UTC").toISOString()).toBe("2026-09-24T07:00:00.000Z");
    expect(nextLocalTime(new Date("2026-09-24T08:00:00Z"), "07:00", "UTC").toISOString()).toBe("2026-09-25T07:00:00.000Z");
    expect(nextLocalTime(new Date("2026-09-24T07:00:00Z"), "07:00", "UTC").toISOString()).toBe("2026-09-25T07:00:00.000Z"); // strictly after
    expect(nextLocalTime(new Date("2026-09-24T20:00:00Z"), "08:00", "Asia/Kolkata").toISOString()).toBe("2026-09-25T02:30:00.000Z");
  });

  it("survives daylight saving changes", () => {
    // Europe/Berlin springs forward on 2026-03-29 (02:00 → 03:00) and falls back on 2026-10-25.
    expect(nextLocalTime(new Date("2026-03-28T12:00:00Z"), "07:00", "Europe/Berlin").toISOString()).toBe("2026-03-29T05:00:00.000Z"); // CEST
    expect(nextLocalTime(new Date("2026-10-24T12:00:00Z"), "07:00", "Europe/Berlin").toISOString()).toBe("2026-10-25T06:00:00.000Z"); // CET
    // 02:30 doesn't exist on 2026-03-29 in Berlin: the first minute after the gap.
    expect(nextLocalTime(new Date("2026-03-28T12:00:00Z"), "02:30", "Europe/Berlin").toISOString()).toBe("2026-03-29T01:00:00.000Z");
  });
});

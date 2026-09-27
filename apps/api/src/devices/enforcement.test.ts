import { describe, expect, it } from "vitest";
import { checkRule } from "./enforcement.js";

const app = (match: "name" | "path", value: string) => checkRule({ kind: "app", match, value }, ["api.nexus.example"]);

describe("block rules can't touch the OS, but can stop Apple's own user apps", () => {
  it("refuses the OS and System Settings", () => {
    for (const v of ["/System/", "/System/Library/CoreServices/Finder.app/", "/System/Applications/", "/System/Applications/System Settings.app/", "C:\\Windows\\System32\\"]) {
      expect(app("path", v), v).toHaveProperty("error");
    }
    expect(app("name", "System Settings")).toHaveProperty("error");
    expect(app("name", "loginwindow")).toHaveProperty("error");
  });
  it("accepts apps under /System/Applications and Safari's Cryptex", () => {
    for (const v of ["/System/Applications/Chess.app/", "/System/Applications/Music.app/", "/System/Applications/Utilities/Terminal.app/", "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/"]) {
      expect(app("path", v), v).toEqual({ value: v });
    }
    expect(app("name", "Chess")).toEqual({ value: "Chess" });
  });
});

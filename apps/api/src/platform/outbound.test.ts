import { describe, expect, it } from "vitest";
import { _isPrivate, assertSafeUrl } from "./outbound.js";

describe("outbound URL guard", () => {
  it("knows private and internal addresses", () => {
    for (const ip of ["10.1.2.3", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"]) {
      expect(_isPrivate(ip), ip).toBe(true);
    }
    for (const ip of ["8.8.8.8", "172.32.0.1", "52.95.110.1", "2606:4700::1111"]) expect(_isPrivate(ip), ip).toBe(false);
  });

  it("refuses internal targets and plain http in production mode", async () => {
    const strict = { allowPrivate: false };
    await expect(assertSafeUrl("http://example.com/scim", strict)).rejects.toThrow("must use https");
    await expect(assertSafeUrl("https://169.254.169.254/latest", strict)).rejects.toThrow("private or internal");
    await expect(assertSafeUrl("https://127.0.0.1:8443/scim", strict)).rejects.toThrow("private or internal");
    await expect(assertSafeUrl("https://[::1]/scim", strict)).rejects.toThrow("private or internal");
    await expect(assertSafeUrl("https://localhost/scim", strict)).rejects.toThrow("private or internal");
    await expect(assertSafeUrl("https://user:pw@example.com/", strict)).rejects.toThrow("credentials");
    await expect(assertSafeUrl("not a url", strict)).rejects.toThrow("valid URL");
  });

  it("lets development point at local fakes", async () => {
    await expect(assertSafeUrl("http://127.0.0.1:9999/scim", { allowPrivate: true })).resolves.toBeInstanceOf(URL);
    await expect(assertSafeUrl("file:///etc/passwd", { allowPrivate: true })).rejects.toThrow("http(s)");
  });
});

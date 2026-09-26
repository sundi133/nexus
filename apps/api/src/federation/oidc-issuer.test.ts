import { describe, expect, it } from "vitest";
import { issuerMismatch } from "./oidc-rp.js";

// What Entra ID really publishes (checked live): /common/v2.0 says "{tenantid}", the v1 endpoint says sts.windows.net.
const T = "72f988bf-86f1-41af-91ab-2d7cd011db47";

describe("issuer mismatch messages", () => {
  it("explains Entra's multi-tenant and v1 endpoints", () => {
    expect(issuerMismatch("https://login.microsoftonline.com/common/v2.0", "https://login.microsoftonline.com/{tenantid}/v2.0")).toContain("multi-tenant endpoint");
    expect(issuerMismatch(`https://login.microsoftonline.com/${T}`, `https://sts.windows.net/${T}/`)).toBe(`That's Entra ID's v1 endpoint. Use the v2.0 issuer: https://login.microsoftonline.com/${T}/v2.0`);
  });
  it("points out a trailing slash, and otherwise quotes both", () => {
    expect(issuerMismatch("https://acme.okta.com/", "https://acme.okta.com")).toContain("trailing slash");
    expect(issuerMismatch("https://a.example", "https://b.example")).toBe('The IdP says its issuer is "https://b.example", not "https://a.example"');
  });
});

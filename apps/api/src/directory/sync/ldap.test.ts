import { adDisabled, guidToString, resolved } from "@nexus/ldap-directory";
import { describe, expect, it } from "vitest";

describe("Active Directory specifics", () => {
  it("formats objectGUID like Windows does (little-endian first three parts)", () => {
    // {C7E5D8A3-1B2C-4D5E-8F90-A1B2C3D4E5F6} as stored on the wire
    const wire = Buffer.from("a3d8e5c72c1b5e4d8f90a1b2c3d4e5f6", "hex");
    expect(guidToString(wire)).toBe("c7e5d8a3-1b2c-4d5e-8f90-a1b2c3d4e5f6");
  });

  it("reads the disabled flag from userAccountControl", () => {
    expect(adDisabled("512")).toBe(false); // NORMAL_ACCOUNT
    expect(adDisabled("514")).toBe(true); // NORMAL_ACCOUNT | ACCOUNTDISABLE
    expect(adDisabled("66050")).toBe(true); // + DONT_EXPIRE_PASSWORD
    expect(adDisabled("")).toBe(false);
  });

  it("uses sensible AD defaults, overridable per attribute", () => {
    const r = resolved({ preset: "active_directory", url: "ldaps://dc:636", bind_dn: "x", base_dn: "DC=corp,DC=example,DC=com", attributes: { email: "userPrincipalName" } });
    expect(r.userFilter).toBe("(&(objectCategory=person)(objectClass=user))");
    expect(r.attrs).toMatchObject({ id: "objectGUID", email: "userPrincipalName", department: "department" });
    expect(r.groupBase).toBe("DC=corp,DC=example,DC=com");
  });
});

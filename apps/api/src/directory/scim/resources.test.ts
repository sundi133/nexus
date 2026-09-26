import { describe, expect, it } from "vitest";
import { groupChanges, matches, parseFilter, patchOps, patchUser, SCHEMA, ScimError, simpleEq, toScimUser, userFields } from "./resources.js";

const ada = toScimUser(
  { id: "u1", email: "ada@acme.com", given_name: "Ada", family_name: "Lovelace", title: "Engineer", department: "R&D", status: "active", created_at: new Date(0), updated_at: new Date(1000) },
  { externalId: "00u1", groups: [{ id: "g1", name: "Eng" }], base: "https://api/scim/v2" },
);

describe("filters", () => {
  it("handles what Okta and Entra ask", () => {
    expect(matches(parseFilter('userName eq "ADA@acme.com"'), ada)).toBe(true); // case-insensitive
    expect(matches(parseFilter('externalId eq "00u1"'), ada)).toBe(true);
    expect(matches(parseFilter('emails[type eq "work"].value eq "ada@acme.com"'), ada)).toBe(true);
    expect(matches(parseFilter('emails[type eq "home"].value eq "ada@acme.com"'), ada)).toBe(false);
    expect(matches(parseFilter('name.familyName sw "love" and active eq true'), ada)).toBe(true);
    expect(matches(parseFilter('userName eq "x@y.com" or title co "engine"'), ada)).toBe(true);
    expect(matches(parseFilter(`${SCHEMA.enterprise}:department eq "r&d"`), ada)).toBe(true);
    expect(matches(parseFilter('groups[value eq "g1"]'), ada)).toBe(true);
    expect(matches(parseFilter("title pr"), ada)).toBe(true);
    expect(simpleEq(parseFilter('userName eq "a@b.co"'), ["userName", "externalId"])).toEqual({ attr: "userName", value: "a@b.co" });
    expect(simpleEq(parseFilter('userName eq "a" and active eq true'), ["userName"])).toBeNull();
  });

  it("refuses what it can't answer correctly", () => {
    for (const bad of ['(userName eq "a")', 'userName xx "a"', "userName eq", 'userName eq "a" nor x eq "b"']) {
      expect(() => parseFilter(bad), bad).toThrow(ScimError);
    }
  });
});

describe("users", () => {
  it("reads the fields Nexus keeps, including Entra's string booleans", () => {
    expect(userFields({ userName: "Ada@Acme.com", name: { givenName: "Ada", familyName: "L" }, active: "False" })).toMatchObject({ email: "ada@acme.com", active: false });
    expect(userFields({ userName: "E12345", emails: [{ value: "home@x.com", type: "home" }, { value: "ADA@acme.com", type: "work" }] }).email).toBe("ada@acme.com");
    expect(userFields({ userName: "a@b.co", [SCHEMA.enterprise]: { department: "Ops" }, externalId: "x" })).toMatchObject({ department: "Ops", external_id: "x", active: true });
    expect(() => userFields({ userName: "not-an-email" })).toThrow(/email/);
    expect(() => userFields({ userName: "a@b.co", active: "maybe" })).toThrow(/active/);
  });

  it("applies Okta's and Entra's PATCH styles", () => {
    // Okta deactivation.
    expect(patchUser(ada, patchOps({ Operations: [{ op: "replace", value: { active: false } }] })).active).toBe(false);
    // Entra: capitalised ops, dotted paths, string booleans, enterprise extension, filtered email path.
    const entra = patchOps({
      schemas: [SCHEMA.patch],
      Operations: [
        { op: "Replace", path: "active", value: "False" },
        { op: "Replace", path: "name.givenName", value: "Augusta" },
        { op: "Add", path: `${SCHEMA.enterprise}:department`, value: "Math" },
        { op: "Replace", path: 'emails[type eq "work"].value', value: "augusta@acme.com" },
        { op: "Replace", value: { "name.familyName": "King", title: "Countess" } },
        { op: "Remove", path: "phoneNumbers" },
      ],
    });
    const u = userFields(patchUser(ada, entra));
    expect(u).toMatchObject({ email: "augusta@acme.com", given_name: "Augusta", family_name: "King", department: "Math", title: "Countess", active: false });
    expect(() => patchOps({ Operations: [{ op: "move", path: "x" }] })).toThrow(/Unsupported op/);
  });
});

describe("groups", () => {
  it("reduces member operations from both vendors", () => {
    // Okta: add and remove with filtered paths.
    expect(
      groupChanges(
        patchOps({ Operations: [{ op: "add", path: "members", value: [{ value: "u1" }, { value: "u2" }] }, { op: "remove", path: 'members[value eq "u3"]' }, { op: "replace", value: { id: "g1", displayName: "Eng" } }] }),
      ),
    ).toEqual({ add: ["u1", "u2"], remove: ["u3"], displayName: "Eng" });
    // Entra: capitalised, remove with a value list, rename by path.
    expect(groupChanges(patchOps({ Operations: [{ op: "Remove", path: "members", value: [{ value: "u1" }] }, { op: "Replace", path: "displayName", value: "Engineering" }] }))).toEqual({
      add: [],
      remove: ["u1"],
      displayName: "Engineering",
    });
    expect(groupChanges(patchOps({ Operations: [{ op: "replace", path: "members", value: [{ value: "u9" }] }] })).replace).toEqual(["u9"]);
  });
});

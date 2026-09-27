import { describe, expect, it } from "vitest";
import { plan, type Local, type Remote, type Settings } from "./plan.js";

const S: Settings = { provider: "google", deprovision: "suspend", sync_groups: true, group_filter: [] };
const ru = (id: string, email: string, extra: Partial<Remote["users"][number]> = {}) => ({ external_id: id, email, given_name: id, family_name: "X", title: "", department: "", active: true, ...extra });
const lu = (id: string, email: string, extra: Partial<Local["users"][number]> = {}) => ({ id, email, given_name: id.replace("L", "r"), family_name: "X", title: "", department: "", status: "active" as const, ...extra });
const link = (external_id: string, local_id: string, suspended_by_sync = false, kind: "user" | "group" = "user") => ({ kind, external_id, local_id, suspended_by_sync });
const empty: Local = { users: [], groups: [], links: [] };

describe("directory sync plan", () => {
  it("creates new people, adopts existing ones by email, and skips unusable accounts", () => {
    const p = plan(
      { users: [ru("r1", "Ann@Acme.com"), ru("r2", "bob@acme.com"), ru("r3", ""), ru("r4", "dup@acme.com"), ru("r5", "DUP@acme.com"), ru("r6", "gone@acme.com", { active: false })], groups: [] },
      { users: [lu("L2", "bob@acme.com")], groups: [], links: [] },
      S,
    );
    expect(p.create_users.map((u) => u.email)).toEqual(["ann@acme.com", "dup@acme.com"]);
    expect(p.link_users).toEqual([{ local_id: "L2", email: "bob@acme.com", external_id: "r2" }]);
    expect(p.skipped.map((x) => x.reason)).toEqual(["No valid email address", "More than one Google Workspace account uses this email"]);
    expect(p.suspend_users).toEqual([]);
  });

  it("updates changed attributes but never blanks local values", () => {
    const p = plan(
      { users: [ru("r1", "ann.new@acme.com", { given_name: "Ann", title: "CFO", department: "" })], groups: [] },
      { users: [lu("L1", "ann@acme.com", { given_name: "Anne", department: "Finance" })], groups: [], links: [link("r1", "L1")] },
      S,
    );
    expect(p.update_users[0]!.changes).toEqual({ email: { from: "ann@acme.com", to: "ann.new@acme.com" }, given_name: { from: "Anne", to: "Ann" }, title: { from: "", to: "CFO" } });
  });

  it("suspends people removed or suspended upstream, and only reactivates its own suspensions", () => {
    const p = plan(
      { users: [ru("r1", "a@acme.com", { active: false }), ru("r3", "c@acme.com"), ru("r4", "d@acme.com")], groups: [] },
      {
        users: [lu("L1", "a@acme.com"), lu("L2", "b@acme.com"), lu("L3", "c@acme.com", { status: "suspended" }), lu("L4", "d@acme.com", { status: "suspended" }), lu("L5", "e@acme.com", { status: "deprovisioned" })],
        groups: [],
        links: [link("r1", "L1"), link("r2", "L2"), link("r3", "L3", true), link("r4", "L4", false), link("r5", "L5")],
      },
      S,
    );
    expect(p.suspend_users).toEqual([
      { local_id: "L1", email: "a@acme.com", reason: "Suspended in Google Workspace" },
      { local_id: "L2", email: "b@acme.com", reason: "Removed from Google Workspace" },
    ]);
    expect(p.reactivate_users).toEqual([{ local_id: "L3", email: "c@acme.com" }]); // L4 was suspended by an admin: left alone
    expect(plan({ users: [], groups: [] }, { users: [lu("L1", "a@acme.com")], groups: [], links: [link("r1", "L1")] }, { ...S, deprovision: "none" }).suspend_users).toEqual([]);
  });

  it("doesn't suspend a linked account that's only skipped this run", () => {
    const p = plan({ users: [ru("r1", "a@acme.com"), ru("r9", "A@acme.com")], groups: [] }, { users: [lu("L1", "a@acme.com")], groups: [], links: [link("r1", "L1")] }, S);
    expect(p.suspend_users).toEqual([]);
  });

  it("scopes to selected groups", () => {
    const remote: Remote = {
      users: [ru("r1", "a@acme.com"), ru("r2", "b@acme.com"), ru("r3", "c@acme.com")],
      groups: [
        { external_id: "g1", name: "Engineering", description: "", member_ids: ["r1", "r2"] },
        { external_id: "g2", name: "Contractors", description: "", member_ids: ["r3"] },
      ],
    };
    const p = plan(remote, { users: [lu("L3", "c@acme.com")], groups: [], links: [link("r3", "L3")] }, { ...S, group_filter: ["g1"] });
    expect(p.create_users.map((u) => u.email)).toEqual(["a@acme.com", "b@acme.com"]);
    expect(p.create_groups.map((g) => g.name)).toEqual(["Engineering"]);
    expect(p.suspend_users).toEqual([{ local_id: "L3", email: "c@acme.com", reason: "No longer in the synced Google Workspace groups" }]);
  });

  it("mirrors group membership for synced groups, including people created in the same run", () => {
    const remote: Remote = {
      users: [ru("r1", "a@acme.com"), ru("r2", "b@acme.com")],
      groups: [{ external_id: "g1", name: "Eng", description: "Builders", member_ids: ["r1", "r2", "r-unknown"] }],
    };
    const local: Local = {
      users: [lu("L1", "a@acme.com"), lu("L9", "z@acme.com")],
      groups: [{ id: "G1", name: "Engineering", description: "", member_ids: ["L9"] }],
      links: [link("r1", "L1"), link("g1", "G1", false, "group")],
    };
    const p = plan(remote, local, S);
    expect(p.update_groups).toEqual([{ local_id: "G1", name: "Engineering", changes: { name: { from: "Engineering", to: "Eng" }, description: { from: "", to: "Builders" } } }]);
    expect(p.membership).toEqual([{ group_external_id: "g1", group_name: "Eng", add: ["r1", "r2"], remove: ["L9"] }]);
    expect(plan(remote, local, { ...S, sync_groups: false }).membership).toEqual([]);
  });

  it("adopts a same-named local group once", () => {
    const p = plan({ users: [], groups: [{ external_id: "g1", name: "Sales", description: "", member_ids: [] }] }, { ...empty, groups: [{ id: "G1", name: "sales", description: "", member_ids: [] }] }, S);
    expect(p.link_groups).toEqual([{ local_id: "G1", name: "Sales", external_id: "g1" }]);
    expect(p.create_groups).toEqual([]);
  });

  it("trips the guard before a mass suspension", () => {
    const users = Array.from({ length: 40 }, (_, i) => lu(`L${i}`, `u${i}@acme.com`));
    const links = users.map((u, i) => link(`r${i}`, u.id));
    const keep = users.slice(0, 30).map((_, i) => ru(`r${i}`, `u${i}@acme.com`));
    const p = plan({ users: keep, groups: [] }, { users, groups: [], links }, S);
    expect(p.guard).toEqual({ tripped: true, suspensions: 10, threshold: 5 });
    const small = plan({ users: users.slice(0, 36).map((_, i) => ru(`r${i}`, `u${i}@acme.com`)), groups: [] }, { users, groups: [], links }, S);
    expect(small.guard.tripped).toBe(false);
  });
});

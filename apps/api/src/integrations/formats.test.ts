import { describe, expect, it } from "vitest";
import { matchesFilter, nexusEvent, ocsfEvent, type AuditRow } from "./formats.js";

const row = (over: Partial<AuditRow> = {}): AuditRow => ({
  id: "01a0d5d5-c840-76cb-be07-d0bdb2f972b8",
  org_id: "01a0d273-fbba-7b6c-81be-39252839809e",
  ts: new Date("2026-09-24T12:00:00Z"),
  type: "user.suspended",
  outcome: "success",
  actor_type: "user",
  actor_id: "01a0d273-fbba-7b6c-81be-000000000001",
  actor_display: "priya@acme.com",
  target_type: "user",
  target_id: "01a0d273-fbba-7b6c-81be-000000000002",
  target_display: "sam@acme.com",
  session_id: null,
  ip: "203.0.113.7",
  user_agent: "Mozilla/5.0",
  details: { reason: "Left" },
  ...over,
});

describe("event formats", () => {
  it("keeps our own JSON simple", () => {
    expect(nexusEvent(row())).toEqual({
      id: row().id,
      type: "user.suspended",
      occurred_at: "2026-09-24T12:00:00.000Z",
      outcome: "success",
      org_id: row().org_id,
      actor: { type: "user", id: row().actor_id, display: "priya@acme.com" },
      target: { type: "user", id: row().target_id, display: "sam@acme.com" },
      ip: "203.0.113.7",
      user_agent: "Mozilla/5.0",
      details: { reason: "Left" },
    });
  });

  it("maps to OCSF classes and activities", () => {
    expect(ocsfEvent(row())).toMatchObject({ class_uid: 3001, activity_id: 6, type_uid: 300106, status_id: 1, severity_id: 1, time: Date.parse("2026-09-24T12:00:00Z"), user: { name: "sam@acme.com" }, src_endpoint: { ip: "203.0.113.7" }, metadata: { event_code: "user.suspended", product: { name: "Votal Nexus" } } });
    expect(ocsfEvent(row({ type: "auth.login", outcome: "failure", target_type: "" }))).toMatchObject({ class_uid: 3002, activity_id: 1, status_id: 2, severity_id: 2 });
    expect(ocsfEvent(row({ type: "sso.login", outcome: "denied", target_type: "application", target_display: "Team Wiki" }))).toMatchObject({ class_uid: 3002, severity_id: 3, resources: [{ type: "application", name: "Team Wiki" }] });
    expect(ocsfEvent(row({ type: "group.members_added", target_type: "group" }))).toMatchObject({ class_uid: 3006, activity_id: 3, type_uid: 300603 });
    expect(ocsfEvent(row({ type: "api_key.revoked", target_type: "api_key" }))).toMatchObject({ class_uid: 3004, activity_id: 4 });
    expect(ocsfEvent(row({ type: "something.new" }))).toMatchObject({ class_uid: 6003, activity_id: 99 });
  });

  it("filters by type prefix", () => {
    expect(matchesFilter([], "user.created")).toBe(true);
    expect(matchesFilter(["user."], "user.created")).toBe(true);
    expect(matchesFilter(["sso.login"], "sso.login")).toBe(true);
    expect(matchesFilter(["sso.login"], "sso.login_failed")).toBe(false);
    expect(matchesFilter(["auth*"], "auth.login")).toBe(true);
    expect(matchesFilter(["user."], "group.created")).toBe(false);
  });
});

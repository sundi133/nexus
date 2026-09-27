import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { runLiveCheck } from "../src/livecheck/checks.js";

/** The live vendor check, against fakes that behave like Entra ID, Intune and PagerDuty, quirks included. */

const TENANT = "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0";
const CLIENT = "11111111-2222-3333-4444-555555555555";
const SECRET = "entra-client-secret-value";
const ROUTING = "pd-routing-key-0123456789";
const users = [
  { id: "u1", givenName: "Sam", surname: "Lee", mail: "sam@acme.com", userPrincipalName: "sam@acme.com", accountEnabled: true, jobTitle: "Eng", department: "R&D", userType: "Member" },
  { id: "u2", givenName: "Sam", surname: "Lee", mail: "SAM@acme.com", userPrincipalName: "sam2@acme.com", accountEnabled: true, userType: "Member" },
  { id: "u3", givenName: "", surname: "", mail: null, userPrincipalName: "svc-backup@acme.onmicrosoft.com", accountEnabled: true, userType: "Member" },
  { id: "u4", givenName: "Pat", surname: "Ng", mail: null, userPrincipalName: "pat_partner.com#EXT#@acme.onmicrosoft.com", accountEnabled: true, userType: "Member" },
  { id: "u5", givenName: "Guest", surname: "One", mail: "g@other.com", userPrincipalName: "g_other.com#EXT#@acme.onmicrosoft.com", accountEnabled: true, userType: "Guest" },
  { id: "u6", givenName: "Ana", surname: "Ruiz", mail: "ana@acme.com", userPrincipalName: "ana@acme.com", accountEnabled: false, userType: "Member" },
];
const devices = [
  { id: "d1", deviceName: "SAM-MBP", serialNumber: "C02ABC123", operatingSystem: "macOS", complianceState: "compliant", isEncrypted: true, userPrincipalName: "sam@acme.com", lastSyncDateTime: new Date().toISOString(), managementState: "managed" },
  { id: "d2", deviceName: "WHITEBOX", serialNumber: "To Be Filled By O.E.M.", operatingSystem: "Windows", complianceState: "compliant", userPrincipalName: "contractor@elsewhere.com", lastSyncDateTime: "2026-01-01T00:00:00Z", managementState: "managed" },
  { id: "d3", deviceName: "VDI-1", serialNumber: "VMW-42", operatingSystem: "Windows", complianceState: "notApplicable", userPrincipalName: "", lastSyncDateTime: "0001-01-01T00:00:00Z", managementState: "managed" },
  { id: "d4", deviceName: "VDI-2", serialNumber: "vmw-42", operatingSystem: "Windows", complianceState: "unknown", userPrincipalName: "ana@acme.com", managementState: "retirePending" },
];
const pd: Record<string, any>[] = [];
let server: http.Server;
let base = "";

beforeAll(async () => {
  server = http.createServer((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c)).on("end", () => {
      const json = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
      const url = new URL(req.url!, base);
      if (url.pathname === `/entra/${TENANT}/oauth2/v2.0/token`) {
        return new URLSearchParams(data).get("client_secret") === SECRET ? json(200, { access_token: "t" }) : json(401, { error: "invalid_client", error_description: `AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app '${CLIENT}'.` });
      }
      if (url.pathname === "/graph/v1.0/users") return json(200, { value: users });
      if (url.pathname === "/graph/v1.0/groups") return json(200, { value: [{ id: "g1", displayName: "Engineering" }, { id: "g2", displayName: "Empty" }] });
      if (url.pathname === "/graph/v1.0/groups/g1/transitiveMembers/microsoft.graph.user") return json(200, { value: [{ id: "u1" }, { id: "u5" }] });
      if (url.pathname.startsWith("/graph/v1.0/groups/")) return json(200, { value: [] });
      if (url.pathname === "/graph/v1.0/deviceManagement/managedDevices") return json(200, { value: devices });
      if (url.pathname === "/pd/v2/enqueue") {
        pd.push(JSON.parse(data));
        return json(202, { status: "success" });
      }
      res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());

const cfg = () => ({ ...loadConfig({ NEXUS_ENV: "dev" }), entraLoginBase: `${base}/entra`, graphBase: `${base}/graph`, pagerdutyEventsUrl: `${base}/pd/v2/enqueue`, allowPrivateOutbound: true });
const env = { LIVE_ENTRA_TENANT_ID: TENANT, LIVE_ENTRA_CLIENT_ID: CLIENT, LIVE_ENTRA_CLIENT_SECRET: SECRET, LIVE_INTUNE: "true", LIVE_PAGERDUTY_ROUTING_KEY: ROUTING };
const opts = { page: false, sendEvents: false, only: null, allowPrivate: true };

describe("live check", () => {
  it("reports directory and MDM quirks, and leaks nothing identifying", async () => {
    const report = await runLiveCheck(env, cfg(), opts);
    const by = Object.fromEntries(report.checks.map((c) => [c.check, c]));

    expect(by.entra_directory).toMatchObject({ status: "warn", stats: { users: 5, active: 4, inactive: 1, groups: 2, largest_group: 2 } });
    expect(by.entra_directory!.stats.email_domains).toEqual({ "acme.com": 3, "acme.onmicrosoft.com": 2 });
    const dir = by.entra_directory!.findings.join("\n");
    for (const f of ["2 people share an email", "1 people have a guest-style #EXT# address", "2 people have only an .onmicrosoft.com address", "1 people have no name", "1 groups are empty", "1 group members aren't among the people read"]) expect(dir).toContain(f);

    expect(by.intune).toMatchObject({ status: "warn", stats: { devices: 4, compliant: 2, noncompliant: 0, unknown: 2 } });
    const mdm = by.intune!.findings.join("\n");
    for (const f of ['1 devices report a placeholder serial (e.g. "To Be Filled By O.E.M.")', "2 devices share a serial", "1 devices have no user", "1 devices are unmanaged or pending retire/wipe", "1 devices haven't checked in with the MDM for 30+ days", 'compliance state Nexus doesn\'t know: "notApplicable"', "1 devices' users aren't in the directory"]) expect(mdm).toContain(f);

    // Paging is opt-in.
    expect(by.pagerduty).toMatchObject({ status: "skipped", findings: [expect.stringContaining("--page")] });
    expect(pd).toHaveLength(0);
    expect(by.jamf!.status).toBe("skipped");

    const text = JSON.stringify(report);
    for (const secret of [SECRET, ROUTING, TENANT, CLIENT, "sam@acme.com", "contractor@elsewhere.com"]) expect(text).not.toContain(secret);
  });

  it("pages and resolves one test incident with --page", async () => {
    const report = await runLiveCheck(env, cfg(), { ...opts, page: true, only: ["pagerduty"] });
    expect(report.checks).toEqual([expect.objectContaining({ check: "pagerduty", status: "warn" })]);
    expect(pd.map((e) => e.event_action)).toEqual(["trigger", "acknowledge", "resolve"]);
    expect(new Set(pd.map((e) => e.dedup_key)).size).toBe(1);
    expect(pd[0]!.payload.summary).toContain("[TEST]");
  });

  it("turns vendor errors into a redacted failure", async () => {
    const report = await runLiveCheck({ ...env, LIVE_ENTRA_CLIENT_SECRET: "wrong-secret-value" }, cfg(), { ...opts, only: ["entra_directory"] });
    const c = report.checks[0]!;
    expect(c).toMatchObject({ status: "fail", error: expect.stringContaining("AADSTS7000215") });
    expect(c.error).not.toContain(CLIENT);
    expect(c.error).toMatch(/<id:[0-9a-f]{8}>/);
  });
});

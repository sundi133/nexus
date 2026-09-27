import { generateKeyPairSync } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { importSPKI, jwtVerify } from "jose";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Android Enterprise through a simulated Google: service account auth, enterprise, policy, enrollment, devices, commands. */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let google: http.Server;
let base = "";
let admin = "";
let helpdesk = "";
let ana = "";
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const SA = { type: "service_account", project_id: "acme-emm", client_email: "nexus@acme-emm.iam.gserviceaccount.com", private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(), private_key_id: "k1" };
const ENTERPRISE = "enterprises/LC00abc123";
const seen: { method: string; path: string; query: Record<string, string>; body: any }[] = [];
const devices: any[] = [];
let tokenAud = "";

async function handle(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url!, base);
  let raw = "";
  for await (const chunk of req) raw += chunk;
  const send = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  if (url.pathname === "/token") {
    // A JWT bearer grant, signed with the service account's key, for the Android Management scope.
    const assertion = new URLSearchParams(raw).get("assertion") ?? "";
    const { payload } = await jwtVerify(assertion, await importSPKI(publicKey.export({ type: "spki", format: "pem" }).toString(), "RS256"), { issuer: SA.client_email, audience: tokenAud });
    if (payload.scope !== "https://www.googleapis.com/auth/androidmanagement") return send(400, { error_description: "bad scope" });
    return send(200, { access_token: "ya29.fake", expires_in: 3600 });
  }
  if (req.headers.authorization !== "Bearer ya29.fake") return send(401, { error: { message: "no token" } });
  const path = url.pathname.replace(/^\/v1\//, "");
  const body = raw ? JSON.parse(raw) : null;
  seen.push({ method: req.method!, path, query: Object.fromEntries(url.searchParams), body });
  if (req.method === "POST" && path === "signupUrls") return send(200, { name: "signupUrls/C123", url: "https://play.google.com/work/adminsignup?token=abc" });
  if (req.method === "POST" && path === "enterprises") {
    if (url.searchParams.get("enterpriseToken") !== "EAxyz-good-token") return send(400, { error: { message: "Invalid enterprise token" } });
    return send(200, { name: ENTERPRISE, enterpriseDisplayName: body.enterpriseDisplayName });
  }
  if (req.method === "PATCH" && path === `${ENTERPRISE}/policies/nexus`) return send(200, { name: path, version: "2" });
  if (req.method === "POST" && path === `${ENTERPRISE}/enrollmentTokens`) return send(200, { name: `${ENTERPRISE}/enrollmentTokens/t1`, value: "ABCDEFGHIJ", qrCode: '{"android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE":{"com.google.android.apps.work.clouddpc.EXTRA_ENROLLMENT_TOKEN":"ABCDEFGHIJ"}}', expirationTimestamp: "2026-10-04T00:00:00Z" });
  if (req.method === "GET" && path === `${ENTERPRISE}/devices`) {
    const page = url.searchParams.get("pageToken") === "p2" ? devices.slice(1) : devices.slice(0, 1);
    return send(200, { devices: page, ...(url.searchParams.get("pageToken") ? {} : devices.length > 1 ? { nextPageToken: "p2" } : {}) });
  }
  if (req.method === "POST" && path.endsWith(":issueCommand")) return send(200, { name: `${path.replace(":issueCommand", "")}/operations/1` });
  if (req.method === "DELETE" && path.startsWith(`${ENTERPRISE}/devices/`)) return send(200, {});
  return send(404, { error: { message: `no route ${req.method} ${path}` } });
}

beforeAll(async () => {
  google = http.createServer((q, r) => void handle(q, r).catch((e) => r.writeHead(500).end(String(e))));
  await new Promise<void>((r) => google.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(google.address() as AddressInfo).port}`;
  tokenAud = `${base}/token`;
  h = await bootApp({ androidApiBase: `${base}/v1`, googleTokenUrl: tokenAud });
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Droid Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Hal", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;
  ana = (await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("ana"), given_name: "Ana", password: PASSWORD } })).body.id;
});
afterAll(async () => {
  google.close();
  await db.end();
  await h.close();
});

describe("Android Enterprise", () => {
  it("takes a service account (sealed), refusing keys that aren't one", async () => {
    expect((await h.call("PUT", "/v1/android/service-account", { token: admin, body: { project_id: "acme-emm", key_json: JSON.stringify({ ...SA, type: "user" }) } })).body.code).toBe("invalid_key");
    expect((await h.call("PUT", "/v1/android/service-account", { token: admin, body: { project_id: "acme-emm", key_json: JSON.stringify({ ...SA, token_uri: "http://169.254.169.254/token" }) } })).body.code).toBe("invalid_key");
    expect((await h.call("PUT", "/v1/android/service-account", { token: helpdesk, body: { project_id: "acme-emm", key_json: JSON.stringify(SA) } })).status).toBe(403);
    const r = await h.call("PUT", "/v1/android/service-account", { token: admin, body: { project_id: "acme-emm", key_json: JSON.stringify(SA) } });
    expect(r.body).toEqual({ service_account: SA.client_email });
    const raw = (await db.query("SELECT service_account FROM android_settings s JOIN organizations o ON o.id = s.org_id WHERE o.name = 'Droid Co'")).rows[0].service_account as Buffer;
    expect(raw.toString("latin1")).not.toContain("PRIVATE KEY");
  });

  it("creates the Android enterprise through Google's sign-up, and applies the policy", async () => {
    const s = await h.call("POST", "/v1/android/signup", { token: admin });
    expect(s.body.url).toContain("play.google.com/work/adminsignup");
    expect(seen.at(-1)!.query).toMatchObject({ projectId: "acme-emm", callbackUrl: `${h.deps.cfg.publicUrl}/android/connected` });
    expect((await h.call("POST", "/v1/android/enterprise", { token: admin, body: { enterprise_token: "EAxyz-wrong-token" } })).body.code).toBe("google_error");
    const e = await h.call("POST", "/v1/android/enterprise", { token: admin, body: { enterprise_token: "EAxyz-good-token" } });
    expect(e.body).toEqual({ name: ENTERPRISE, display_name: "Droid Co" });
    const patch = seen.find((x) => x.method === "PATCH")!;
    expect(patch.body).toMatchObject({
      passwordPolicies: [expect.objectContaining({ passwordScope: "SCOPE_DEVICE", passwordMinimumLength: 6 }), expect.objectContaining({ passwordScope: "SCOPE_PROFILE" })],
      maximumTimeToLock: "300000",
      advancedSecurityOverrides: { untrustedAppsPolicy: "DISALLOW_INSTALL" },
    });
    const status = (await h.call("GET", "/v1/android", { token: helpdesk })).body;
    expect(status).toMatchObject({ service_account: SA.client_email, enterprise: { name: ENTERPRISE }, policy_applied_at: expect.any(String) });
  });

  it("changes the policy, including apps to install or block", async () => {
    const policy = { password_min_length: 8, lock_after_minutes: 2, block_unknown_sources: true, disable_camera: true, apps: [{ package: "com.Slack", install: "force" }, { package: "com.zhiliaoapp.musically", install: "blocked" }] };
    expect((await h.call("PUT", "/v1/android/policy", { token: admin, body: { ...policy, apps: [{ package: "not a package", install: "force" }] } })).status).toBe(400);
    expect((await h.call("PUT", "/v1/android/policy", { token: admin, body: policy })).status).toBe(200);
    expect(seen.filter((x) => x.method === "PATCH").at(-1)!.body).toMatchObject({
      cameraAccess: "CAMERA_ACCESS_DISABLED",
      maximumTimeToLock: "120000",
      applications: [{ packageName: "com.Slack", installType: "FORCE_INSTALLED" }, { packageName: "com.zhiliaoapp.musically", installType: "BLOCKED" }],
    });
  });

  it("makes enrollment tokens that say whose phone it'll be", async () => {
    const t = await h.call("POST", "/v1/android/enrollment-tokens", { token: helpdesk, body: { kind: "company", user_id: ana, days: 7 } });
    expect(t.status).toBe(201);
    expect(t.body).toMatchObject({ value: "ABCDEFGHIJ", enroll_url: "https://enterprise.google.com/android/enroll?et=ABCDEFGHIJ", qr_code: expect.stringContaining("EXTRA_ENROLLMENT_TOKEN") });
    expect(seen.at(-1)!.body).toEqual({ policyName: `${ENTERPRISE}/policies/nexus`, duration: "604800s", allowPersonalUsage: "PERSONAL_USAGE_DISALLOWED", additionalData: JSON.stringify({ user_id: ana }) });
  });

  it("mirrors the devices Google reports, across pages, with owners and compliance", async () => {
    devices.push(
      { name: `${ENTERPRISE}/devices/d1`, managementMode: "DEVICE_OWNER", ownership: "COMPANY_OWNED", appliedState: "ACTIVE", policyCompliant: true, enrollmentTokenData: JSON.stringify({ user_id: ana }), hardwareInfo: { brand: "google", model: "Pixel 8", serialNumber: "PX8SER1" }, softwareInfo: { androidVersion: "15", securityPatchLevel: "2026-08-05" }, enrollmentTime: "2026-09-20T10:00:00Z", lastStatusReportTime: "2026-09-27T08:00:00Z" },
      { name: `${ENTERPRISE}/devices/d2`, managementMode: "PROFILE_OWNER", ownership: "PERSONALLY_OWNED", appliedState: "ACTIVE", policyCompliant: false, nonComplianceDetails: [{ settingName: "passwordPolicies", nonComplianceReason: "USER_ACTION" }], hardwareInfo: { brand: "samsung", model: "Galaxy S24", serialNumber: "R5CX123" }, softwareInfo: { androidVersion: "14" } },
    );
    expect((await h.call("POST", "/v1/android/sync", { token: helpdesk })).body).toEqual({ devices: 2 });
    const list = (await h.call("GET", "/v1/android/devices", { token: helpdesk })).body.data;
    expect(list.find((d: any) => d.model === "Pixel 8")).toMatchObject({ kind: "company", policy_compliant: true, assigned_user: { id: ana }, security_patch: "2026-08-05" });
    expect(list.find((d: any) => d.model === "Galaxy S24")).toMatchObject({ kind: "work_profile", policy_compliant: false, non_compliance: [{ setting: "passwordPolicies", reason: "USER_ACTION" }], assigned_user: null });
    // Removed at Google: removed here on the next sync.
    devices.splice(1, 1);
    await h.call("POST", "/v1/android/sync", { token: helpdesk });
    expect((await h.call("GET", "/v1/android/devices", { token: helpdesk })).body.data).toHaveLength(1);
  });

  it("sends commands and removes devices, with the checks each needs", async () => {
    await h.call("POST", "/v1/android/sync", { token: helpdesk });
    devices.push({ name: `${ENTERPRISE}/devices/d3`, managementMode: "PROFILE_OWNER", hardwareInfo: { model: "Pixel 7", serialNumber: "WP7" } });
    await h.call("POST", "/v1/android/sync", { token: helpdesk });
    const list = (await h.call("GET", "/v1/android/devices", { token: admin })).body.data;
    const pixel = list.find((d: any) => d.model === "Pixel 8").id;
    const work = list.find((d: any) => d.model === "Pixel 7").id;
    const lost = await h.call("POST", `/v1/android/devices/${pixel}/commands`, { token: admin, body: { command: "start_lost_mode", reason: "Left in a taxi", message: "Please call IT", phone: "+1 555 0100" } });
    expect(lost.status).toBe(202);
    expect(seen.at(-1)).toMatchObject({ path: `${ENTERPRISE}/devices/d1:issueCommand`, body: { type: "START_LOST_MODE", startLostModeParams: { lostMessage: { defaultMessage: "Please call IT" }, lostPhoneNumber: { defaultMessage: "+1 555 0100" } } } });
    expect((await h.call("POST", `/v1/android/devices/${work}/commands`, { token: admin, body: { command: "reboot", reason: "Stuck" } })).body.code).toBe("unsupported");
    expect((await h.call("POST", `/v1/android/devices/${work}/commands`, { token: admin, body: { command: "lock", reason: "Stolen bag" } })).status).toBe(202);
    expect((await h.call("DELETE", `/v1/android/devices/${work}`, { token: helpdesk, body: { reason: "Left", confirm: "WP7" } })).status).toBe(403);
    expect((await h.call("DELETE", `/v1/android/devices/${work}`, { token: admin, body: { reason: "Left", confirm: "nope" } })).body.code).toBe("confirm_mismatch");
    expect((await h.call("DELETE", `/v1/android/devices/${work}`, { token: admin, body: { reason: "Left the company", confirm: "WP7" } })).status).toBe(204);
    expect(seen.at(-1)).toMatchObject({ method: "DELETE", path: `${ENTERPRISE}/devices/d3`, query: { wipeReasonMessage: "Left the company" } });
    const audits = (await db.query("SELECT type, details FROM audit_events WHERE type LIKE 'android.%' AND details->>'reason' IS NOT NULL ORDER BY ts")).rows.map((r) => [r.type, r.details.command ?? r.details.effect]);
    expect(audits).toEqual(expect.arrayContaining([["android.command_sent", "start_lost_mode"], ["android.device_removed", "work profile removed"]]));
  });
});

import { generateKeyPairSync, randomUUID } from "node:crypto";
import http from "node:http";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { importSPKI, jwtVerify } from "jose";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { notifyRoles, notifyUsers } from "../src/notify/send.js";
import { RoutingPushSender } from "../src/platform/push.js";
import { ApnsSender } from "../src/platform/push-apns.js";
import { FcmSender } from "../src/platform/push-fcm.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** Notification delivery (NTF-04/06/07/11): APNs, FCM, email and Slack, per preferences, logged. */

const apnsKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const fcmKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const apnsSeen: { path: string; headers: http2.IncomingHttpHeaders; body: any }[] = [];
const fcmSeen: { token: string; body: any }[] = [];
const slackSeen: any[] = [];
const RUN = randomUUID().slice(0, 8); // push tokens are unique across all tenants
const GOOD = { ios: `good-ios-${RUN}`, android: `good-android-${RUN}` };
const DEAD = { ios: `dead-ios-${RUN}`, android: `dead-android-${RUN}` };

let apns: http2.Http2Server;
let web: http.Server;
let base = "";
let apnsBase = "";

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";
let adminId = "";

const run = async () => {
  await owner.query("UPDATE jobs SET run_at = now() WHERE org_id = $1 AND status = 'queued'", [orgId]);
  await h.jobs.runOnce({ orgId });
};
const notify = (severity: "info" | "warning" | "critical", title: string, body = "Details inside Nexus only") =>
  h.deps.db.tenant(orgId, (tx) => notifyUsers(tx, orgId, [adminId], { category: "security.alert", severity, title, body, link: "/audit" }));
const latestNotification = async () => (await h.call("GET", "/v1/me/notifications?limit=1&filter=all", { token: admin })).body.data[0];
const deliveries = async (id: string) => (await h.call("GET", `/v1/me/notifications/${id}/deliveries`, { token: admin })).body.data as { channel: string; status: string; detail: string }[];

beforeAll(async () => {
  // Fake APNs: HTTP/2, checks the ES256 provider token like Apple does.
  apns = http2.createServer();
  apns.on("stream", (stream: http2.ServerHttp2Stream, headers) => {
    let data = "";
    stream.on("data", (c) => (data += c)).on("end", async () => {
      try {
        const jwt = String(headers.authorization).replace(/^bearer /, "");
        await jwtVerify(jwt, await importSPKI(apnsKey.publicKey.export({ type: "spki", format: "pem" }).toString(), "ES256"), { issuer: "TEAM123456" });
      } catch {
        stream.respond({ ":status": 403 });
        return stream.end(JSON.stringify({ reason: "InvalidProviderToken" }));
      }
      apnsSeen.push({ path: String(headers[":path"]), headers, body: JSON.parse(data) });
      const dead = String(headers[":path"]).endsWith(DEAD.ios);
      stream.respond({ ":status": dead ? 410 : 200 });
      stream.end(dead ? JSON.stringify({ reason: "Unregistered" }) : undefined);
    });
  });
  await new Promise<void>((r) => apns.listen(0, "127.0.0.1", r));
  apnsBase = `http://127.0.0.1:${(apns.address() as AddressInfo).port}`;

  // Fake Google OAuth + FCM, and a Slack incoming webhook.
  web = http.createServer((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c)).on("end", () => {
      if (req.url === "/token") return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ access_token: "fcm-access", expires_in: 3600 }));
      if (req.url?.startsWith("/v1/projects/nexus-test/messages:send")) {
        if (req.headers.authorization !== "Bearer fcm-access") return res.writeHead(401).end();
        const body = JSON.parse(data);
        fcmSeen.push({ token: body.message.token, body });
        if (body.message.token === DEAD.android) return res.writeHead(404, { "content-type": "application/json" }).end(JSON.stringify({ error: { status: "NOT_FOUND", details: [{ errorCode: "UNREGISTERED" }] } }));
        return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ name: "projects/nexus-test/messages/1" }));
      }
      if (req.url === "/slack") {
        slackSeen.push(JSON.parse(data));
        return res.writeHead(200).end("ok");
      }
      res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => web.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(web.address() as AddressInfo).port}`;

  const push = new RoutingPushSender({
    ios: new ApnsSender({ teamId: "TEAM123456", keyId: "KEY1234567", bundleId: "ai.votal.nexus", privateKey: apnsKey.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), production: false, base: apnsBase }),
    android: new FcmSender({ projectId: "nexus-test", clientEmail: "fcm@nexus-test.iam.gserviceaccount.com", privateKey: fcmKey.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), tokenUrl: `${base}/token`, base }),
  });
  h = await bootApp({}, { push });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  const email = uniqueEmail("frank");
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Kruger", email, password: PASSWORD, given_name: "Frank" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token: admin })).body;
  orgId = me.organization.id;
  adminId = me.user.id;
  await run(); // anything from signup
  for (const [platform, token] of [["ios", GOOD.ios], ["android", GOOD.android], ["ios", DEAD.ios], ["android", DEAD.android]]) {
    await owner.query("INSERT INTO push_registrations (id, org_id, user_id, platform, token, last_seen_at) VALUES ($1, $2, $3, $4, $5, now())", [randomUUID(), orgId, adminId, platform, token]);
  }
  apnsSeen.length = 0;
  fcmSeen.length = 0;
});
afterAll(async () => {
  apns.close();
  web.close();
  await owner.end();
  await h.close();
});

describe("push and email", () => {
  it("delivers a critical alert everywhere, with content-free pushes", async () => {
    await notify("critical", "Admin account contained", "Secret details that must not reach Apple or Google");
    await run();
    const n = await latestNotification();

    const ios = apnsSeen.find((x) => x.path === `/3/device/${GOOD.ios}`)!;
    expect(ios.headers["apns-topic"]).toBe("ai.votal.nexus");
    expect(ios.headers["apns-priority"]).toBe("10");
    expect(ios.body).toEqual({ aps: { alert: { title: "Security alert" }, sound: "default", "thread-id": "security.alert" }, category: "security.alert", id: n.id });
    const android = fcmSeen.find((x) => x.token === GOOD.android)!;
    expect(android.body.message).toMatchObject({ notification: { title: "Security alert" }, data: { category: "security.alert", id: n.id }, android: { priority: "HIGH" } });
    expect(JSON.stringify([...apnsSeen, ...fcmSeen])).not.toContain("Secret details");

    const mail = [...h.mailer.sent].reverse().find((m) => m.subject.includes("Admin account contained"))!;
    expect(mail.subject).toBe("[Critical] Admin account contained");
    expect(mail.text).toContain("Secret details"); // email is the full notification

    const log = await deliveries(n.id);
    expect(log.find((d) => d.channel === "push")).toMatchObject({ status: "sent", detail: "2 of 4 phones; removed 2 expired" });
    expect(log.find((d) => d.channel === "email")).toMatchObject({ status: "sent" });
  });

  it("forgets phones whose app was uninstalled", async () => {
    const regs = await owner.query("SELECT token FROM push_registrations WHERE user_id = $1 ORDER BY token", [adminId]);
    expect(regs.rows.map((r) => r.token)).toEqual([GOOD.android, GOOD.ios]);
  });

  it("respects preferences, but never for critical alerts", async () => {
    expect((await h.call("PUT", "/v1/me/notification-preferences", { token: admin, body: { email: "critical", push: "important" } })).status).toBe(200);
    apnsSeen.length = 0;
    const mailsBefore = h.mailer.sent.length;
    await notify("warning", "Device out of compliance");
    await run();
    const warning = await latestNotification();
    expect(apnsSeen).toHaveLength(1);
    expect(apnsSeen[0]!.headers["apns-priority"]).toBe("5");
    expect(apnsSeen[0]!.body.aps.alert.title).toBe("Needs your attention");
    expect(h.mailer.sent.length).toBe(mailsBefore);
    expect((await deliveries(warning.id)).find((d) => d.channel === "email")).toMatchObject({ status: "skipped", detail: "Below their email setting (critical)" });

    await h.call("PUT", "/v1/me/notification-preferences", { token: admin, body: { email: "critical", push: "critical" } });
    await notify("critical", "Break-glass account used");
    await run();
    expect(h.mailer.sent.at(-1)!.subject).toBe("[Critical] Break-glass account used");
    await notify("info", "Weekly summary ready");
    await run();
    const info = await latestNotification();
    expect((await deliveries(info.id)).map((d) => d.status)).toEqual(["skipped", "skipped"]);
  });

  it("delivers once even if the job runs again", async () => {
    await notify("critical", "Once only");
    await run();
    const n = await latestNotification();
    apnsSeen.length = 0;
    const { deliverNotification } = await import("../src/notify/deliver.js");
    await deliverNotification(h.deps, orgId, n.id);
    expect(apnsSeen).toHaveLength(0);
  });
});

describe("Slack", () => {
  it("gets each org alert once, above the chosen severity", async () => {
    expect((await h.call("PUT", "/v1/org/alert-channels", { token: admin, body: { slack_webhook_url: "ftp://x", slack_min_severity: "warning" } })).body.code).toBe("unsafe_url");
    const r = await h.call("PUT", "/v1/org/alert-channels", { token: admin, body: { slack_webhook_url: `${base}/slack`, slack_min_severity: "warning" } });
    expect(r.body).toEqual({ slack_configured: true, slack_min_severity: "warning" });
    expect((await h.call("POST", "/v1/org/alert-channels/test", { token: admin, body: {} })).status).toBe(204);
    expect(slackSeen.at(-1).text).toContain("Test alert from Votal Nexus");

    // Two admins, one alert → one Slack message.
    await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("second"), given_name: "Second", password: PASSWORD, roles: ["admin"] } });
    await run(); // (granting admin raises its own alert)
    slackSeen.length = 0;
    await h.deps.db.tenant(orgId, (tx) => notifyRoles(tx, orgId, ["owner", "admin"], { category: "security.alert", severity: "critical", title: "Impossible travel for sam@kruger.test", body: "Sign-ins from Oslo and Lima 20 minutes apart.", link: "/users" }));
    await h.deps.db.tenant(orgId, (tx) => notifyRoles(tx, orgId, ["owner", "admin"], { category: "devices.update", severity: "info", title: "Agent 1.3 available", link: "/agent-updates" }));
    await run();
    expect(slackSeen).toHaveLength(1);
    expect(slackSeen[0].text).toBe(":rotating_light: Impossible travel for sam@kruger.test");
    expect(slackSeen[0].blocks[1].elements[0].url).toBe("http://localhost:3100/users");

    const off = await h.call("PUT", "/v1/org/alert-channels", { token: admin, body: { slack_webhook_url: null, slack_min_severity: "warning" } });
    expect(off.body.slack_configured).toBe(false);
  });
});

import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { signedMessage } from "../src/auth/push.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** A software Nexus Mobile: an Ed25519 key pair like the one kept in the phone's keystore. */
class SoftPhone {
  private readonly key: KeyObject;
  readonly publicKey: string;
  token = "";
  factorId = "";
  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    this.key = privateKey;
    this.publicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
  }
  sign(id: string, decision: "approve" | "deny", choice: number | null) {
    return sign(null, Buffer.from(signedMessage(id, decision, choice)), this.key).toString("base64url");
  }
}

let h: Awaited<ReturnType<typeof bootApp>>;
const email = uniqueEmail("pushowner");
let webToken = "";
const phone = new SoftPhone();

beforeAll(async () => {
  h = await bootApp();
  webToken = (await h.call("POST", "/v1/signup", { body: { organization_name: "Hooli", email, password: PASSWORD, given_name: "Gavin" } })).body.token;
});
afterAll(() => h.close());

async function pair(forToken: string, device: SoftPhone, name = "Gavin's iPhone") {
  const start = await h.call("POST", "/v1/me/factors/push/pairing", { token: forToken });
  expect(start.status).toBe(201);
  expect(start.body.pairing_url).toMatch(/^nexus:\/\/pair\?code=nxp_/);
  const r = await h.call("POST", "/v1/devices/pair", {
    body: { code: start.body.code, public_key: device.publicKey, device_name: name, platform: "ios", push_token: `apns-${Math.random()}` },
  });
  expect(r.status).toBe(200);
  device.token = r.body.token;
  device.factorId = r.body.factor_id;
  return { code: start.body.code, result: r };
}

async function startSignIn() {
  const login = await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } });
  expect(login.body.session.state).toBe("pending_mfa");
  const push = await h.call("POST", "/v1/auth/mfa/push", { token: login.body.token });
  expect(push.status).toBe(201);
  return { webToken: login.body.token as string, challengeId: push.body.challenge_id as string, number: push.body.number as number };
}

describe("push MFA", () => {
  it("pairs a phone with a one-time code", async () => {
    const { code, result } = await pair(webToken, phone);
    expect(result.body).toMatchObject({ user: { email }, organization: { name: "Hooli" } });
    const me = await h.call("GET", "/v1/me", { token: phone.token });
    expect(me.body.session).toMatchObject({ client: "mobile", state: "active" });
    const factors = await h.call("GET", "/v1/me/factors", { token: webToken });
    expect(factors.body.data).toContainEqual(expect.objectContaining({ type: "push", name: "Gavin's iPhone", verified: true }));
    // The code works once.
    const again = await h.call("POST", "/v1/devices/pair", { body: { code, public_key: phone.publicKey, device_name: "x", platform: "ios" } });
    expect(again.body.code).toBe("pairing_invalid");
  });

  it("approves a sign-in when the right number is tapped", async () => {
    const pushesBefore = h.push.sent.length;
    const s = await startSignIn();
    expect(h.push.sent.length - pushesBefore).toBe(1);
    expect(h.push.sent.at(-1)!.payload).toEqual({ title: "Sign-in request", category: "auth.mfa_challenge", id: s.challengeId, priority: "high" });

    const pending = await h.call("GET", "/v1/me/mfa-challenges", { token: phone.token });
    const ch = pending.body.data.find((c: { id: string }) => c.id === s.challengeId);
    expect(ch.choices).toHaveLength(3);
    expect(ch.choices).toContain(s.number);
    expect(ch).not.toHaveProperty("number"); // the phone never learns the answer
    expect(ch.context.user_agent).toBe("nexus-tests");

    const r = await h.call("POST", `/v1/me/mfa-challenges/${s.challengeId}/respond`, {
      token: phone.token,
      body: { decision: "approve", choice: s.number, factor_id: phone.factorId, signature: phone.sign(s.challengeId, "approve", s.number) },
    });
    expect(r.body).toEqual({ status: "approved", reason: null });
    expect((await h.call("GET", `/v1/auth/mfa/push/${s.challengeId}`, { token: s.webToken })).body.status).toBe("approved");
    expect((await h.call("GET", "/v1/auth/session", { token: s.webToken })).body.state).toBe("active");

    const again = await h.call("POST", `/v1/me/mfa-challenges/${s.challengeId}/respond`, {
      token: phone.token,
      body: { decision: "approve", choice: s.number, factor_id: phone.factorId, signature: phone.sign(s.challengeId, "approve", s.number) },
    });
    expect(again.body.code).toBe("challenge_decided");
  });

  it("rejects approvals not signed by the paired key", async () => {
    const s = await startSignIn();
    const r = await h.call("POST", `/v1/me/mfa-challenges/${s.challengeId}/respond`, {
      token: phone.token,
      body: { decision: "approve", choice: s.number, factor_id: phone.factorId, signature: new SoftPhone().sign(s.challengeId, "approve", s.number) },
    });
    expect(r.body.code).toBe("invalid_signature");
    // A signature for a different number can't be reused either.
    const wrongMsg = await h.call("POST", `/v1/me/mfa-challenges/${s.challengeId}/respond`, {
      token: phone.token,
      body: { decision: "approve", choice: s.number, factor_id: phone.factorId, signature: phone.sign(s.challengeId, "approve", s.number + 1) },
    });
    expect(wrongMsg.body.code).toBe("invalid_signature");
    expect((await h.call("GET", `/v1/auth/mfa/push/${s.challengeId}`, { token: s.webToken })).body.status).toBe("pending");
  });

  it("treats a wrong number as an attack: denies, revokes the waiting session, alerts security", async () => {
    const s = await startSignIn();
    const wrong = [10, 11, 12].find((n) => n !== s.number)!;
    const r = await h.call("POST", `/v1/me/mfa-challenges/${s.challengeId}/respond`, {
      token: phone.token,
      body: { decision: "approve", choice: wrong, factor_id: phone.factorId, signature: phone.sign(s.challengeId, "approve", wrong) },
    });
    expect(r.body).toEqual({ status: "denied", reason: "wrong_number" });
    expect((await h.call("GET", "/v1/auth/session", { token: s.webToken })).status).toBe(401);
  });

  it("'This wasn't me' blocks the sign-in and raises a critical alert", async () => {
    const s = await startSignIn();
    const r = await h.call("POST", `/v1/me/mfa-challenges/${s.challengeId}/respond`, {
      token: phone.token,
      body: { decision: "deny", reason: "not_me", factor_id: phone.factorId, signature: phone.sign(s.challengeId, "deny", null) },
    });
    expect(r.body).toEqual({ status: "denied", reason: "not_me" });
    expect((await h.call("GET", "/v1/auth/session", { token: s.webToken })).status).toBe(401);
    const inbox = await h.call("GET", "/v1/me/notifications", { token: phone.token });
    expect(inbox.body.data[0]).toMatchObject({ severity: "warning", title: "We blocked a sign-in to your account" });
    expect(inbox.body.data.some((n: { severity: string; category: string }) => n.category === "security.alert" && n.severity === "critical")).toBe(true);
    const audit = await h.call("GET", "/v1/audit/events?type=auth.mfa&outcome=denied", { token: phone.token });
    expect(audit.body.data.map((e: { details: { reason: string } }) => e.details.reason)).toEqual(expect.arrayContaining(["not_me", "wrong_number"]));
  });

  it("completes mandatory MFA enrollment by pairing a phone", async () => {
    await h.call("PATCH", "/v1/org/settings", { token: phone.token, body: { mfa_policy: "everyone" } });
    const member = uniqueEmail("member");
    await h.call("POST", "/v1/users", { token: phone.token, body: { email: member, given_name: "Dinesh", password: PASSWORD } });
    const login = await h.call("POST", "/v1/auth/login", { body: { email: member, password: PASSWORD } });
    expect(login.body.session.state).toBe("enroll_mfa");
    await pair(login.body.token, new SoftPhone(), "Dinesh's Pixel");
    expect((await h.call("GET", "/v1/auth/session", { token: login.body.token })).body.state).toBe("active");
  });

  it("unpairing a phone signs that phone out", async () => {
    const extra = new SoftPhone();
    await pair(phone.token, extra, "Old phone");
    expect((await h.call("GET", "/v1/me", { token: extra.token })).status).toBe(200);
    const del = await h.call("DELETE", `/v1/me/factors/${extra.factorId}`, { token: phone.token });
    expect(del.status).toBe(204);
    expect((await h.call("GET", "/v1/me", { token: extra.token })).status).toBe(401);
  });
});

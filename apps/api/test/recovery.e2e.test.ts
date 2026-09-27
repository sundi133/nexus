import { createHash } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";

/** Account recovery (AUTH-01/02/08): recovery codes, password reset and change, breached passwords, MFA help. */

const BREACHED = "password1234567"; // pretend it's in every breach list
const hibpRequests: { path: string; padding: string | undefined }[] = [];
let hibpDown = false;
let hibp: http.Server;

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
const user = { email: "", secret: "", token: "", id: "" };
let codes: string[] = [];

const sha1 = (s: string) => createHash("sha1").update(s).digest("hex").toUpperCase();
const login = (email: string, password: string) => h.call("POST", "/v1/auth/login", { body: { email, password } });
const lastMailTo = (to: string) => [...h.mailer.sent].reverse().find((m) => m.to === to);

beforeAll(async () => {
  hibp = http.createServer((req, res) => {
    hibpRequests.push({ path: req.url!, padding: req.headers["add-padding"] as string | undefined });
    if (hibpDown) return res.writeHead(503).end();
    const prefix = req.url!.split("/").pop()!;
    const bad = sha1(BREACHED);
    // Real responses: many suffixes, some padding entries with count 0.
    const lines = ["0018A45C4D1DEF81644B54AB7F969B88D65:1", "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0"];
    if (bad.startsWith(prefix)) lines.push(`${bad.slice(5)}:3861493`);
    res.writeHead(200).end(lines.join("\r\n"));
  });
  await new Promise<void>((r) => hibp.listen(0, "127.0.0.1", r));
  h = await bootApp({ hibpBase: `http://127.0.0.1:${(hibp.address() as AddressInfo).port}` });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Pendant", email: uniqueEmail("art"), password: PASSWORD, given_name: "Art" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });

  user.email = uniqueEmail("elaine");
  user.id = (await h.call("POST", "/v1/users", { token: admin, body: { email: user.email, given_name: "Elaine", password: PASSWORD } })).body.id;
  user.token = (await login(user.email, PASSWORD)).body.token;
  const f = await h.call("POST", "/v1/me/factors/totp", { token: user.token, body: {} });
  user.secret = f.body.secret;
  await h.call("POST", `/v1/me/factors/${f.body.id}/verify`, { token: user.token, body: { code: totpCode(user.secret) } });
});
afterAll(async () => {
  hibp.close();
  await owner.end();
  await h.close();
});

describe("breached passwords", () => {
  it("are refused wherever a password is set, using only a 5-character hash prefix", async () => {
    const r = await h.call("POST", "/v1/signup", { body: { organization_name: "Weak", email: uniqueEmail("weak"), password: BREACHED, given_name: "W" } });
    expect(r).toMatchObject({ status: 400, body: { code: "breached_password" } });
    expect(r.body.title).toContain("3,861,493 known data breaches");
    expect((await h.call("POST", "/v1/users", { token: admin, body: { email: uniqueEmail("w2"), given_name: "W", password: BREACHED } })).body.code).toBe("breached_password");
    const req = hibpRequests.at(-1)!;
    expect(req.path).toBe(`/range/${sha1(BREACHED).slice(0, 5)}`);
    expect(req.padding).toBe("true");
    expect(hibpRequests.some((x) => x.path.includes(sha1(BREACHED).slice(5)))).toBe(false); // the rest of the hash never leaves
  });

  it("fail open when the check is unavailable", async () => {
    hibpDown = true;
    expect((await h.call("POST", "/v1/signup", { body: { organization_name: "Open", email: uniqueEmail("open"), password: "a-perfectly-fine-passphrase", given_name: "O" } })).status).toBe(201);
    hibpDown = false;
  });
});

describe("recovery codes", () => {
  it("are generated after MFA is set up, shown once", async () => {
    const r = await h.call("POST", "/v1/me/recovery-codes", { token: user.token, body: {} });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    codes = r.body.codes;
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) expect(c).toMatch(/^[a-hj-km-np-z2-9]{5}-[a-hj-km-np-z2-9]{5}$/);
    expect((await h.call("GET", "/v1/me/recovery-codes", { token: user.token })).body).toMatchObject({ remaining: 10 });
  });

  it("finish sign-in once each, in any formatting", async () => {
    const s = (await login(user.email, PASSWORD)).body.token;
    const info = await h.call("GET", "/v1/auth/session", { token: s });
    expect(info.body).toMatchObject({ state: "pending_mfa", factors: ["totp"], recovery_codes: 10 });
    const r = await h.call("POST", "/v1/auth/mfa/recovery-code", { token: s, body: { code: ` ${codes[0]!.toUpperCase().replace("-", " ")} ` } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.remaining).toBe(9);
    expect((await h.call("GET", "/v1/me", { token: s })).status).toBe(200);

    const s2 = (await login(user.email, PASSWORD)).body.token;
    expect((await h.call("POST", "/v1/auth/mfa/recovery-code", { token: s2, body: { code: codes[0] } })).body.code).toBe("invalid_code");
    expect((await h.call("POST", "/v1/auth/mfa/recovery-code", { token: s2, body: { code: "aaaaa-bbbbb" } })).body.code).toBe("invalid_code");
    const audit = await h.call("GET", "/v1/audit/events?type=auth.mfa", { token: admin });
    expect(audit.body.data.some((e: { details: { factor: string }; outcome: string }) => e.details.factor === "recovery_code" && e.outcome === "failure")).toBe(true);
  });

  it("warn when running low, and old ones die when regenerated", async () => {
    await owner.query("UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND used_at IS NULL AND code_hash <> ALL($2)", [
      user.id,
      codes.slice(1, 3).map((c) => createHash("sha256").update(c.replace("-", "")).digest()),
    ]);
    const s = (await login(user.email, PASSWORD)).body.token;
    expect((await h.call("POST", "/v1/auth/mfa/recovery-code", { token: s, body: { code: codes[1] } })).body.remaining).toBe(1);
    const inbox = await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: s });
    expect(inbox.body.data[0]).toMatchObject({ title: "Only 1 recovery code left", severity: "warning" });

    const fresh = (await h.call("POST", "/v1/me/recovery-codes", { token: s, body: {} })).body.codes;
    expect(fresh).toHaveLength(10);
    const s2 = (await login(user.email, PASSWORD)).body.token;
    expect((await h.call("POST", "/v1/auth/mfa/recovery-code", { token: s2, body: { code: codes[2] } })).body.code).toBe("invalid_code");
    codes = fresh;
  });
});

describe("lost every MFA method", () => {
  it("lets the person ask admins for help, once an hour", async () => {
    const s = (await login(user.email, PASSWORD)).body.token;
    expect((await h.call("POST", "/v1/auth/mfa/help", { token: s, body: {} })).status).toBe(202);
    expect((await h.call("POST", "/v1/auth/mfa/help", { token: s, body: {} })).status).toBe(202);
    const inbox = (await h.call("GET", "/v1/me/notifications?limit=10&filter=all", { token: admin })).body.data.filter((n: { title: string }) => n.title === `${user.email} can't use any MFA method`);
    expect(inbox).toHaveLength(1);
    expect(inbox[0].link).toBe(`/users/${user.id}`);
  });
});

describe("password reset", () => {
  it("never reveals whether an account exists", async () => {
    const before = h.mailer.sent.length;
    expect((await h.call("POST", "/v1/auth/password-reset", { body: { email: uniqueEmail("nobody") } })).status).toBe(202);
    expect(h.mailer.sent.length).toBe(before);
  });

  it("sets a new password, signs out everywhere, and still requires MFA", async () => {
    const live = (await login(user.email, PASSWORD)).body.token;
    await h.call("POST", "/v1/auth/mfa/totp", { token: live, body: { code: totpCode(user.secret, 1) } });
    expect((await h.call("POST", "/v1/auth/password-reset", { body: { email: user.email.toUpperCase() } })).status).toBe(202);
    const mail = lastMailTo(user.email)!;
    expect(mail.subject).toBe("Reset your Nexus password");
    const token = decodeURIComponent(/token=([^"&\s]+)/.exec(mail.text)![1]!);

    expect((await h.call("POST", "/v1/auth/password-reset/complete", { body: { token, password: BREACHED } })).body.code).toBe("breached_password");
    const r = await h.call("POST", "/v1/auth/password-reset/complete", { body: { token, password: "a-brand-new-passphrase" } });
    expect(r.status, JSON.stringify(r.body)).toBe(204);
    expect((await h.call("GET", "/v1/me", { token: live })).status).toBe(401); // signed out everywhere
    expect(lastMailTo(user.email)!.subject).toBe("Your Nexus password was changed");
    expect((await login(user.email, PASSWORD)).status).toBe(401);
    const s = await login(user.email, "a-brand-new-passphrase");
    expect(s.body.session.state).toBe("pending_mfa"); // a reset link is not a second factor
    expect((await h.call("POST", "/v1/auth/password-reset/complete", { body: { token, password: "another-passphrase-x" } })).body.code).toBe("reset_invalid");
    const audit = await h.call("GET", "/v1/audit/events?type=user.password_reset", { token: admin });
    expect(audit.body.data[0]).toMatchObject({ actor: { display: user.email }, details: { sessions_revoked: expect.any(Number) } });
  });

  it("links expire", async () => {
    await h.call("POST", "/v1/auth/password-reset", { body: { email: user.email } });
    const token = decodeURIComponent(/token=([^"&\s]+)/.exec(lastMailTo(user.email)!.text)![1]!);
    await owner.query("UPDATE password_resets SET expires_at = now() - interval '1 second' WHERE user_id = $1", [user.id]);
    expect((await h.call("POST", "/v1/auth/password-reset/complete", { body: { token, password: "yet-another-passphrase" } })).body.code).toBe("reset_invalid");
  });
});

describe("password change", () => {
  it("checks the current password and signs out other sessions", async () => {
    const a = (await login(user.email, "a-brand-new-passphrase")).body.token;
    expect((await h.call("POST", "/v1/auth/mfa/recovery-code", { token: a, body: { code: codes[5] } })).status).toBe(200);
    const b = (await login(user.email, "a-brand-new-passphrase")).body.token;
    expect((await h.call("PUT", "/v1/me/password", { token: a, body: { current_password: "wrong-wrong-wrong", new_password: "changed-passphrase-1" } })).body.code).toBe("wrong_password");
    expect((await h.call("PUT", "/v1/me/password", { token: a, body: { current_password: "a-brand-new-passphrase", new_password: "changed-passphrase-1" } })).status).toBe(204);
    expect((await h.call("GET", "/v1/me", { token: a })).status).toBe(200);
    expect((await h.call("GET", "/v1/auth/session", { token: b })).status).toBe(401);
  });
});

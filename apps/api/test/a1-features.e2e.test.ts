import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";
import { SoftAuthenticator } from "./webauthn.js";

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client; // owner-role connection, only to simulate time passing
let ownerToken = "";
let ownerEmail = "";
let ownerTotp = "";

beforeAll(async () => {
  h = await bootApp();
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  ownerEmail = uniqueEmail("owner");
  const r = await h.call("POST", "/v1/signup", { body: { organization_name: "Initech", email: ownerEmail, password: PASSWORD, given_name: "Bill" } });
  ownerToken = r.body.token;
});
afterAll(async () => {
  await owner.end();
  await h.close();
});

const inviteToken = (to: string) => {
  const mail = [...h.mailer.sent].reverse().find((m) => m.to === to);
  const m = mail?.text.match(/token=([^\s&]+)/);
  return m ? decodeURIComponent(m[1]!) : null;
};

describe("MFA policy and secure baseline", () => {
  it("previews impact, then applies the baseline and tells admins", async () => {
    const before = await h.call("GET", "/v1/org/baseline", { token: ownerToken });
    expect(before.body.items.find((i: { id: string }) => i.id === "mfa_everyone")).toMatchObject({ compliant: false, current: "Admins only" });
    expect(before.body.score).toBeLessThan(1);

    const impact = await h.call("GET", "/v1/org/settings/impact?mfa_policy=everyone", { token: ownerToken });
    expect(impact.body.users_to_enroll).toBe(1); // just the owner so far

    const applied = await h.call("POST", "/v1/org/baseline/apply", { token: ownerToken });
    expect(applied.status).toBe(200);
    expect(applied.body.applied).toEqual(["mfa_policy", "owners_require_passkey"]);
    expect((await h.call("GET", "/v1/org/settings", { token: ownerToken })).body.mfa_policy).toBe("everyone");

    const audit = await h.call("GET", "/v1/audit/events?type=org.settings_updated", { token: ownerToken });
    expect(audit.body.data[0].details).toMatchObject({ via: "secure_baseline", changes: { mfa_policy: { from: "admins", to: "everyone" } } });
    const inbox = await h.call("GET", "/v1/me/notifications", { token: ownerToken });
    expect(inbox.body.data.map((n: { category: string }) => n.category)).toContain("security.policy_change");
  });

  it("requires recent MFA (step-up) for security settings once you have a factor", async () => {
    // This org opts out of owner passkeys (admin-safety tests cover them), so any factor steps up.
    await owner.query("UPDATE organizations SET settings = settings || '{\"owners_require_passkey\": false}' WHERE id = (SELECT org_id FROM users WHERE email = $1)", [ownerEmail]);
    const start = await h.call("POST", "/v1/me/factors/totp", { token: ownerToken, body: {} });
    ownerTotp = start.body.secret;
    await h.call("POST", `/v1/me/factors/${start.body.id}/verify`, { token: ownerToken, body: { code: totpCode(ownerTotp) } });
    // Fresh MFA: allowed.
    expect((await h.call("PATCH", "/v1/org/settings", { token: ownerToken, body: { session_ttl_hours: 8 } })).status).toBe(200);
    // Pretend the MFA was an hour ago.
    await owner.query("UPDATE sessions SET mfa_at = now() - interval '1 hour' WHERE mfa_at IS NOT NULL AND revoked_at IS NULL AND user_id = (SELECT id FROM users WHERE email = $1)", [ownerEmail]);
    const denied = await h.call("PATCH", "/v1/org/settings", { token: ownerToken, body: { session_ttl_hours: 24 } });
    expect(denied.status).toBe(401);
    expect(denied.body.code).toBe("step_up_required");
    expect(denied.headers.get("www-authenticate")).toContain("insufficient_user_authentication");
    // Step up with the next TOTP window, then retry.
    expect((await h.call("POST", "/v1/auth/mfa/totp", { token: ownerToken, body: { code: totpCode(ownerTotp, 1) } })).status).toBe(200);
    expect((await h.call("PATCH", "/v1/org/settings", { token: ownerToken, body: { session_ttl_hours: 24 } })).status).toBe(200);
  });

  it("puts members without MFA into enrollment when the policy is 'everyone'", async () => {
    const email = uniqueEmail("member");
    await h.call("POST", "/v1/users", { token: ownerToken, body: { email, given_name: "Milton", password: PASSWORD } });
    const login = await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } });
    expect(login.body.session.state).toBe("enroll_mfa");
    expect(login.body.mfa.enrollment_required).toBe(true);
    const t = login.body.token;
    const info = await h.call("GET", "/v1/auth/session", { token: t });
    expect(info.body).toMatchObject({ state: "enroll_mfa", email, organization_name: "Initech" });
    expect((await h.call("GET", "/v1/me", { token: t })).body.code).toBe("mfa_enrollment_required");
  });
});

describe("invitations", () => {
  const email = uniqueEmail("peter");
  let userId = "";

  it("creates a staged user and emails an invitation", async () => {
    const r = await h.call("POST", "/v1/users", { token: ownerToken, body: { email, given_name: "Peter", family_name: "Gibbons", invite: true } });
    expect(r.status).toBe(201);
    expect(r.body.status).toBe("staged");
    userId = r.body.id;
    const mail = h.mailer.sent.find((m) => m.to === email);
    expect(mail?.subject).toBe("You're invited to Initech");
    expect(mail?.html).toContain("Accept invitation");
    expect(inviteToken(email)).toMatch(/^nxi_/);

    const login = await h.call("POST", "/v1/auth/login", { body: { email, password: "anything-at-all-123" } });
    expect(login.status).toBe(401); // no password set yet
  });

  it("re-sending invalidates the old link", async () => {
    const first = inviteToken(email)!;
    expect((await h.call("POST", `/v1/users/${userId}/invite`, { token: ownerToken })).status).toBe(200);
    const second = inviteToken(email)!;
    expect(second).not.toBe(first);
    expect((await h.call("GET", `/v1/invitations/${first}`)).body.code).toBe("invitation_invalid");
    expect((await h.call("GET", `/v1/invitations/${second}`)).body).toMatchObject({ email, organization_name: "Initech" });
  });

  it("accepting sets the password, activates the user, and can only happen once", async () => {
    const token = inviteToken(email)!;
    const r = await h.call("POST", "/v1/invitations/accept", { body: { token, password: PASSWORD } });
    expect(r.status).toBe(200);
    expect(r.body.session.state).toBe("enroll_mfa"); // org requires MFA for everyone
    expect((await h.call("POST", "/v1/invitations/accept", { body: { token, password: PASSWORD } })).body.code).toBe("invitation_invalid");
    const user = await h.call("GET", `/v1/users/${userId}`, { token: ownerToken });
    expect(user.body.status).toBe("active");
    const inbox = await h.call("GET", "/v1/me/notifications", { token: ownerToken });
    expect(inbox.body.data.map((n: { category: string }) => n.category)).toContain("directory.invite_accepted");
    expect((await h.call("POST", `/v1/users/${userId}/invite`, { token: ownerToken })).body.code).toBe("not_staged");
  });
});

describe("CSV import", () => {
  const ana = uniqueEmail("ana");
  const bob = uniqueEmail("bob");
  // Built lazily: ownerEmail is only known after beforeAll.
  const csvFor = () => [
    'Email,First Name,Last Name,Department,Groups',
    `${ana},Ana,Ruiz,Engineering,"Engineering;All staff"`,
    `"${bob}",Bob,"Smith, Jr.",Sales,All staff`,
    `not-an-email,Carl,X,,`,
    `${ana},Ana,Again,,`,
    `${ownerEmail},Bill,Owner,,`,
  ].join("\r\n");
  let csv = "";

  it("previews without writing anything", async () => {
    csv = csvFor();
    const r = await h.call("POST", "/v1/users/import", { token: ownerToken, body: { csv, dry_run: true } });
    expect(r.status).toBe(200);
    expect(r.body.summary).toMatchObject({ create: 2, skip: 2, error: 1 });
    expect(r.body.summary.new_groups.sort()).toEqual(["All staff", "Engineering"]);
    expect(r.body.rows[1]).toMatchObject({ email: bob, name: "Bob Smith, Jr.", action: "create" });
    expect(r.body.rows[2]).toMatchObject({ line: 4, action: "error" });
    expect((await h.call("GET", `/v1/users?q=${ana}`, { token: ownerToken })).body.data).toHaveLength(0);
  });

  it("reports emails already used by another organization instead of failing", async () => {
    const other = await h.call("POST", "/v1/signup", { body: { organization_name: "Chotchkie's", email: uniqueEmail("joanna"), password: PASSWORD, given_name: "Joanna" } });
    const theirs = uniqueEmail("taken");
    await h.call("POST", "/v1/users", { token: other.body.token, body: { email: theirs, given_name: "Taken" } });
    const r = await h.call("POST", "/v1/users/import", { token: ownerToken, body: { csv: `email,first name\n${theirs},Taken`, dry_run: true } });
    expect(r.body.rows[0]).toMatchObject({ action: "error", message: "This email is already used by another Nexus account" });
  });

  it("imports users into groups and invites them", async () => {
    const sentBefore = h.mailer.sent.length;
    const r = await h.call("POST", "/v1/users/import", { token: ownerToken, body: { csv, dry_run: false } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.summary.create).toBe(2);
    expect(h.mailer.sent.length - sentBefore).toBe(2);
    const users = await h.call("GET", "/v1/users?status=staged", { token: ownerToken });
    expect(users.body.data.map((u: { email: string }) => u.email)).toEqual(expect.arrayContaining([ana, bob]));
    const groups = await h.call("GET", "/v1/groups", { token: ownerToken });
    const all = groups.body.data.find((g: { name: string }) => g.name === "All staff");
    expect(all.member_count).toBe(2);
    // Idempotent: a second run only skips.
    const again = await h.call("POST", "/v1/users/import", { token: ownerToken, body: { csv, dry_run: true } });
    expect(again.body.summary).toMatchObject({ create: 0, skip: 4, error: 1 });
  });
});

describe("passkeys", () => {
  const email = uniqueEmail("pk");
  const device = new SoftAuthenticator();
  let token = "";

  it("registers a passkey during mandatory enrollment, which activates the session", async () => {
    await h.call("POST", "/v1/users", { token: ownerToken, body: { email, given_name: "Samir", password: PASSWORD } });
    token = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    const opts = await h.call("POST", "/v1/me/factors/webauthn/options", { token });
    expect(opts.status).toBe(200);
    expect(opts.body.options.rp).toMatchObject({ id: "localhost", name: "Votal Nexus" });
    const reg = await h.call("POST", "/v1/me/factors/webauthn", {
      token,
      body: { challenge_id: opts.body.challenge_id, name: "MacBook Touch ID", response: device.register(opts.body.options) },
    });
    expect(reg.status).toBe(201);
    expect(reg.body).toMatchObject({ type: "webauthn", name: "MacBook Touch ID", verified: true });
    expect((await h.call("GET", "/v1/auth/session", { token })).body.state).toBe("active");
    // The challenge was single-use.
    const replay = await h.call("POST", "/v1/me/factors/webauthn", {
      token,
      body: { challenge_id: opts.body.challenge_id, response: device.register(opts.body.options) },
    });
    expect(replay.body.code).toBe("challenge_expired");
  });

  it("signs in without a password", async () => {
    const opts = await h.call("POST", "/v1/auth/passkey/options", { body: { email } });
    expect(opts.body.options.allowCredentials).toHaveLength(1);
    const r = await h.call("POST", "/v1/auth/passkey", {
      body: { email, challenge_id: opts.body.challenge_id, response: device.authenticate(opts.body.options) },
    });
    expect(r.status).toBe(200);
    expect(r.body.session.state).toBe("active");
    const me = await h.call("GET", "/v1/me", { token: r.body.token });
    expect(me.body.session.mfa_at).not.toBeNull();
  });

  it("works as the second factor after a password", async () => {
    const login = await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } });
    expect(login.body.mfa).toMatchObject({ required: true, factors: ["webauthn"] });
    const opts = await h.call("POST", "/v1/auth/mfa/webauthn/options", { token: login.body.token });
    const r = await h.call("POST", "/v1/auth/mfa/webauthn", {
      token: login.body.token,
      body: { challenge_id: opts.body.challenge_id, response: device.authenticate(opts.body.options) },
    });
    expect(r.body.session.state).toBe("active");
  });

  it("rejects another device's key and doesn't reveal unknown emails", async () => {
    const opts = await h.call("POST", "/v1/auth/passkey/options", { body: { email } });
    const r = await h.call("POST", "/v1/auth/passkey", {
      body: { email, challenge_id: opts.body.challenge_id, response: new SoftAuthenticator().authenticate(opts.body.options) },
    });
    expect(r.status).toBe(401);
    const ghost = await h.call("POST", "/v1/auth/passkey/options", { body: { email: uniqueEmail("ghost") } });
    expect(ghost.status).toBe(200);
    expect(ghost.body.options.allowCredentials).toEqual([]);
  });
});

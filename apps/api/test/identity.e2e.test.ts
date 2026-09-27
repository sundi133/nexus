import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, totpCode, uniqueEmail } from "./harness.js";

let h: Awaited<ReturnType<typeof bootApp>>;
beforeAll(async () => {
  h = await bootApp();
});
afterAll(async () => {
  await h.close();
});

describe("walking skeleton: identity core", () => {
  const ownerEmail = uniqueEmail("owner");
  let ownerToken = "";
  let totpSecret = "";

  it("signs up an organization with an owner", async () => {
    const r = await h.call("POST", "/v1/signup", {
      body: { organization_name: "Acme Robotics", email: ownerEmail, password: PASSWORD, given_name: "Olivia", family_name: "Owner" },
    });
    expect(r.status).toBe(201);
    expect(r.body.token).toMatch(/^nxs_/);
    expect(r.body.session.state).toBe("active");
    ownerToken = r.body.token;

    const me = await h.call("GET", "/v1/me", { token: ownerToken });
    expect(me.status).toBe(200);
    expect(me.body.roles).toEqual(["owner"]);
    expect(me.body.permissions).toContain("admins:manage");
    expect(me.body.organization.slug).toMatch(/^acme-robotics/);
  });

  it("rejects invalid input with problem+json", async () => {
    const r = await h.call("POST", "/v1/signup", { body: { organization_name: "x", email: "nope", password: "short", given_name: "" } });
    expect(r.status).toBe(400);
    expect(r.headers.get("content-type")).toContain("application/problem+json");
    expect(r.body.code).toBe("invalid_request");
    expect(r.body.errors.map((e: { path: string }) => e.path)).toEqual(expect.arrayContaining(["email", "password"]));
  });

  it("flags an admin without MFA as critical in Needs attention", async () => {
    const r = await h.call("GET", "/v1/overview", { token: ownerToken });
    expect(r.status).toBe(200);
    expect(r.body.needs_attention[0]).toMatchObject({ id: "admins_without_mfa", severity: "critical" });
    expect(r.body.needs_attention.map((i: { id: string }) => i.id)).toContain("single_owner");
  });

  it("enrolls TOTP and requires it at the next sign-in", async () => {
    const start = await h.call("POST", "/v1/me/factors/totp", { token: ownerToken, body: {} });
    expect(start.status).toBe(201);
    expect(start.body.otpauth_url).toMatch(/^otpauth:\/\/totp\//);
    totpSecret = start.body.secret;

    const bad = await h.call("POST", `/v1/me/factors/${start.body.id}/verify`, { token: ownerToken, body: { code: "000000" } });
    expect(bad.status).toBe(400);
    const ok = await h.call("POST", `/v1/me/factors/${start.body.id}/verify`, { token: ownerToken, body: { code: totpCode(totpSecret) } });
    expect(ok.status).toBe(200);
    expect(ok.body.verified).toBe(true);

    expect((await h.call("POST", "/v1/auth/logout", { token: ownerToken })).status).toBe(204);
    expect((await h.call("GET", "/v1/me", { token: ownerToken })).status).toBe(401);

    const login = await h.call("POST", "/v1/auth/login", { body: { email: ownerEmail, password: PASSWORD } });
    expect(login.status).toBe(200);
    expect(login.body.session.state).toBe("pending_mfa");
    expect(login.body.mfa).toEqual({ required: true, enrollment_required: false, factors: ["totp"] });
    const pending = login.body.token;

    const blocked = await h.call("GET", "/v1/me", { token: pending });
    expect(blocked.status).toBe(401);
    expect(blocked.body.code).toBe("mfa_required");

    expect((await h.call("POST", "/v1/auth/mfa/totp", { token: pending, body: { code: "123456" } })).body.code).toBe("invalid_code");
    // The enrollment code's time-step is spent, so the same code is refused (replay protection)...
    const replay = await h.call("POST", "/v1/auth/mfa/totp", { token: pending, body: { code: totpCode(totpSecret) } });
    expect(replay.body.code).toBe("invalid_code");
    // ...and the next window's code works.
    const mfa = await h.call("POST", "/v1/auth/mfa/totp", { token: pending, body: { code: totpCode(totpSecret, 1) } });
    expect(mfa.status).toBe(200);
    expect(mfa.body.session.state).toBe("active");
    ownerToken = pending;
    expect((await h.call("GET", "/v1/me", { token: ownerToken })).status).toBe(200);
  });

  it("does not reveal whether an email exists", async () => {
    const a = await h.call("POST", "/v1/auth/login", { body: { email: ownerEmail, password: "wrong-password-123" } });
    const b = await h.call("POST", "/v1/auth/login", { body: { email: uniqueEmail("ghost"), password: "wrong-password-123" } });
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(a.body).toEqual(b.body);
  });

  let staffId = "";
  const staffEmail = uniqueEmail("sam");

  it("creates users and alerts owners when admin rights are granted", async () => {
    const r = await h.call("POST", "/v1/users", {
      token: ownerToken,
      body: { email: staffEmail, given_name: "Sam", family_name: "Staff", department: "Eng", password: PASSWORD, roles: ["helpdesk"] },
    });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ email: staffEmail, roles: ["helpdesk"], mfa_enrolled: false, status: "active" });
    staffId = r.body.id;

    const dup = await h.call("POST", "/v1/users", { token: ownerToken, body: { email: staffEmail.toUpperCase(), given_name: "Dup" } });
    expect(dup.status).toBe(409);

    const inbox = await h.call("GET", "/v1/me/notifications?filter=unread", { token: ownerToken });
    expect(inbox.body.data.map((n: { category: string }) => n.category)).toContain("security.admin_change");
    expect(inbox.body.unread_count).toBeGreaterThan(0);
  });

  it("makes new admins enroll MFA before anything else, then enforces permissions server-side", async () => {
    const login = await h.call("POST", "/v1/auth/login", { body: { email: staffEmail, password: PASSWORD, client: "mobile" } });
    const staffToken = login.body.token;
    // Default org policy requires MFA for admins; helpdesk is an admin role.
    expect(login.body.session.state).toBe("enroll_mfa");
    expect((await h.call("GET", "/v1/users", { token: staffToken })).body.code).toBe("mfa_enrollment_required");
    const start = await h.call("POST", "/v1/me/factors/totp", { token: staffToken, body: {} });
    await h.call("POST", `/v1/me/factors/${start.body.id}/verify`, { token: staffToken, body: { code: totpCode(start.body.secret) } });
    expect((await h.call("GET", "/v1/auth/session", { token: staffToken })).body.state).toBe("active");
    // helpdesk can read users but cannot manage admin roles
    expect((await h.call("GET", "/v1/users", { token: staffToken })).status).toBe(200);
    const denied = await h.call("PUT", `/v1/users/${staffId}/roles`, { token: staffToken, body: { roles: ["owner"] } });
    expect(denied.status).toBe(403);
  });

  it("filters and searches users", async () => {
    const enrolled = await h.call("GET", "/v1/users?mfa=enrolled", { token: ownerToken });
    expect(enrolled.body.data.map((u: { email: string }) => u.email).sort()).toEqual([ownerEmail, staffEmail].sort());
    const q = await h.call("GET", `/v1/users?q=${encodeURIComponent("sam staff")}`, { token: ownerToken });
    expect(q.body.data).toHaveLength(1);
  });

  it("contains a user: suspended, signed out everywhere, admins alerted", async () => {
    const r = await h.call("POST", `/v1/users/${staffId}/contain`, { token: ownerToken, body: { reason: "Impossible travel" } });
    expect(r.status).toBe(200);
    expect(r.body.user.status).toBe("suspended");
    expect(r.body.effects.sessions_revoked).toBe(1);

    const login = await h.call("POST", "/v1/auth/login", { body: { email: staffEmail, password: PASSWORD } });
    expect(login.status).toBe(403);
    expect(login.body.code).toBe("account_inactive");

    const self = await h.call("POST", `/v1/users/${(await h.call("GET", "/v1/me", { token: ownerToken })).body.user.id}/contain`, {
      token: ownerToken,
      body: {},
    });
    expect(self.body.code).toBe("cannot_target_self");
  });

  it("records everything in the audit log", async () => {
    const r = await h.call("GET", "/v1/audit/events?limit=100", { token: ownerToken });
    const types = r.body.data.map((e: { type: string }) => e.type);
    for (const t of ["org.created", "user.created", "user.mfa_enrolled", "auth.login", "auth.mfa", "auth.logout", "user.contain"]) {
      expect(types).toContain(t);
    }
    const failures = await h.call("GET", "/v1/audit/events?type=auth.*&outcome=failure", { token: ownerToken });
    expect(failures.body.data.length).toBeGreaterThanOrEqual(3); // bad password + bad TOTP + replayed TOTP

    const contain = r.body.data.find((e: { type: string }) => e.type === "user.contain");
    expect(contain.details.reason).toBe("Impossible travel");
    expect(contain.actor.display).toBe(ownerEmail);
    expect(contain.target.display).toBe(staffEmail);
  });

  it("paginates with opaque cursors", async () => {
    const p1 = await h.call("GET", "/v1/audit/events?limit=3", { token: ownerToken });
    expect(p1.body.data).toHaveLength(3);
    const p2 = await h.call("GET", `/v1/audit/events?limit=3&cursor=${p1.body.next_cursor}`, { token: ownerToken });
    expect(p2.body.data[0].id < p1.body.data[2].id).toBe(true);
  });

  it("isolates tenants", async () => {
    const other = await h.call("POST", "/v1/signup", {
      body: { organization_name: "Globex", email: uniqueEmail("globex"), password: PASSWORD, given_name: "Gina" },
    });
    const t = other.body.token;
    expect((await h.call("GET", `/v1/users/${staffId}`, { token: t })).status).toBe(404);
    const users = await h.call("GET", "/v1/users", { token: t });
    expect(users.body.data).toHaveLength(1);
    const audit = await h.call("GET", "/v1/audit/events?limit=200", { token: t });
    expect(audit.body.data.every((e: { target: { display: string } }) => e.target.display !== staffEmail)).toBe(true);
  });

  it("streams inbox updates in real time over SSE", async () => {
    const res = await h.app.request("/v1/me/stream", { headers: { authorization: `Bearer ${ownerToken}` } });
    expect(res.headers.get("content-type")).toContain("text/event-stream");
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    const until = async (needle: string) => {
      const deadline = Date.now() + 5000;
      while (!buf.includes(needle)) {
        if (Date.now() > deadline) throw new Error(`timed out waiting for ${needle}; got: ${buf}`);
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value);
      }
    };
    await until("event: ready");
    // Any admin alert creates an inbox row → NOTIFY → SSE.
    await h.call("POST", "/v1/users", { token: ownerToken, body: { email: uniqueEmail("ana"), given_name: "Ana", roles: ["readonly"] } });
    await until("event: notification");
    await reader.cancel();
  });
});

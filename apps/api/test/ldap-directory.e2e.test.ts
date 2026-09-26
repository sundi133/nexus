import { readFileSync } from "node:fs";
import { type IO, run } from "@nexus/cli";
import { Attribute, Change, Client } from "ldapts";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/**
 * Active Directory / LDAP (on-prem directories) against a real OpenLDAP server, with
 * LDAPS and StartTLS on a private CA. Run the server with test/fixtures/ldap (see CI):
 * NEXUS_TEST_LDAP_HOST=localhost NEXUS_TEST_LDAP_CA=<ca.crt>
 */
const HOST = process.env.NEXUS_TEST_LDAP_HOST;

describe.skipIf(!HOST)("Active Directory / LDAP", () => {
  let h: Awaited<ReturnType<typeof bootApp>>;
  let owner: pg.Client;
  let admin = "";
  let connId = "";
  const ca = HOST ? readFileSync(process.env.NEXUS_TEST_LDAP_CA!, "utf8") : "";
  const creds = (extra: Record<string, unknown> = {}) => ({
    provider: "ldap",
    preset: "openldap",
    url: `ldaps://${HOST}:1636`,
    ca_cert: ca,
    bind_dn: "cn=svc-nexus,ou=service,dc=acme,dc=test",
    bind_password: "service-password",
    base_dn: "dc=acme,dc=test",
    user_base_dn: "ou=people,dc=acme,dc=test",
    disabled_filter: "(employeeType=disabled)",
    ...extra,
  });
  const login = (email: string, password: string) => h.call("POST", "/v1/auth/login", { body: { email, password } });
  const user = async (email: string) => (await h.call("GET", `/v1/users?q=${encodeURIComponent(email)}`, { token: admin })).body.data[0];

  beforeAll(async () => {
    h = await bootApp();
    owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
    await owner.connect();
    // The directory's people have fixed emails: clear them from earlier runs.
    await owner.query("DELETE FROM users WHERE email LIKE '%@acme.test'");
    const email = uniqueEmail("root");
    admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "AD Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
    await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  });
  afterAll(async () => {
    await owner?.end();
    await h?.close();
  });

  it("tests the connection over LDAPS and StartTLS, trusting only the given CA", async () => {
    const t = await h.call("POST", "/v1/directory/test", { token: admin, body: creds() });
    expect(t.status, JSON.stringify(t.body)).toBe(200);
    expect(t.body).toMatchObject({ users: 4, active_users: 3 });
    expect(t.body.groups.map((g: any) => `${g.name}:${g.members}`)).toEqual(["engineering:2", "platform:1", "sales:2"]);
    const tls = await h.call("POST", "/v1/directory/test", { token: admin, body: creds({ url: `ldap://${HOST}:1389`, start_tls: true }) });
    expect(tls.body.users).toBe(4);
    const noCa = await h.call("POST", "/v1/directory/test", { token: admin, body: creds({ ca_cert: undefined }) });
    expect(noCa.status).toBe(422); // an untrusted certificate is refused
    const plain = await h.call("POST", "/v1/directory/test", { token: admin, body: creds({ url: `ldap://${HOST}:1389` }) });
    expect(plain.body.title ?? plain.body.detail).toMatch(/unencrypted/);
    const wrong = await h.call("POST", "/v1/directory/test", { token: admin, body: creds({ bind_password: "nope" }) });
    expect(wrong.body.title).toMatch(/rejected the credentials/);
  });

  it("syncs people, disabled accounts and nested groups", async () => {
    const r = await h.call("POST", "/v1/directory/connections", { token: admin, body: { ...creds({ password_auth: true }), name: "Corp AD" } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    connId = r.body.data[0].id;
    expect(r.body.data[0]).toMatchObject({ provider: "ldap", provider_name: "Active Directory / LDAP", account: expect.stringContaining("directory passwords") });
    await h.call("POST", `/v1/directory/connections/${connId}/sync`, { token: admin, body: {} });
    await h.jobs.runOnce({ orgId: (await h.call("GET", "/v1/me", { token: admin })).body.organization.id });
    const c = (await h.call("GET", "/v1/directory/connections", { token: admin })).body.data[0];
    expect(c, JSON.stringify({ status: c.last_status, error: c.last_error, result: c.last_result, linked: [c.linked_users, c.linked_groups] })).toMatchObject({ last_status: "ok", linked_users: 3, linked_groups: 3 });
    const alice = (await h.call("GET", `/v1/users/${(await user("alice@acme.test")).id}`, { token: admin })).body;
    expect(alice, JSON.stringify(alice)).toMatchObject({ status: "staged", title: "Staff Engineer", department: "Engineering", managed_by: "Active Directory / LDAP" });
    expect(await user("dave@acme.test")).toBeUndefined(); // disabled in the directory: no account is created
    const groups = (await h.call("GET", "/v1/groups", { token: admin })).body.data;
    expect(groups.find((g: any) => g.name === "engineering").member_count).toBe(2); // alice, and bob via platform
    expect(h.mailer.sent.filter((m) => m.to.endsWith("@acme.test"))).toEqual([]); // no invitations with directory passwords
  });

  it("signs people in with their directory password", async () => {
    expect((await login("alice@acme.test", "wrong-password-123")).status).toBe(401);
    const ok = await login("alice@acme.test", "alice-password");
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect((await user("alice@acme.test")).status).toBe("active"); // staged until the directory vouched for them
    expect((await login("dave@acme.test", "dave-password")).status).toBe(401); // disabled in the directory: never got an account
  });

  it("doesn't let the directory decide an admin's password", async () => {
    const carol = await user("carol@acme.test");
    expect((await login("carol@acme.test", "carol-password")).status).toBe(200);
    await h.call("PUT", `/v1/users/${carol.id}/roles`, { token: admin, body: { roles: ["admin"] } });
    expect((await login("carol@acme.test", "carol-password")).status).toBe(401); // admins use a Nexus password
  });

  it("leaves password changes to the directory", async () => {
    const t = (await login("bob@acme.test", "bob-password")).body.token;
    const r = await h.call("PUT", "/v1/me/password", { token: t, body: { current_password: "bob-password", new_password: "a-brand-new-password-1" } });
    expect(r.body.code).toBe("directory_password");
    await h.call("POST", "/v1/auth/password-reset", { body: { email: "bob@acme.test" } });
    expect(h.mailer.sent.filter((m) => m.to === "bob@acme.test")).toEqual([]);
  });

  it("refuses private directory hosts where the deployment doesn't allow them", async () => {
    const strict = await bootApp({ allowPrivateDirectory: false });
    const t = (await strict.call("POST", "/v1/signup", { body: { organization_name: "Strict AD", email: uniqueEmail("s"), password: PASSWORD, given_name: "S" } })).body.token;
    await strict.call("PATCH", "/v1/org/settings", { token: t, body: { mfa_policy: "off" } });
    const r = await strict.call("POST", "/v1/directory/test", { token: t, body: creds({ url: "ldaps://127.0.0.1:1636" }) });
    expect(r.body.title).toMatch(/private address/);
    await strict.close();
  });

  describe("the on-prem connector (nexus directory push)", () => {
    let token = "";
    let scimToken = "";
    let orgId = "";
    const files = new Map<string, string>();
    const out = { text: "", err: "" };
    const io = (): IO => ({
      env: { NEXUS_SCIM_TOKEN: scimToken, LDAP_BIND_PASSWORD: "service-password" },
      fetch: ((url: string, init?: RequestInit) => h.app.request(new URL(url).pathname + new URL(url).search, init)) as typeof fetch,
      out: (s: string) => void (out.text += s),
      err: (s: string) => void (out.err += s),
      readFile: async (p: string) => files.get(p) ?? (() => { throw new Error(`ENOENT ${p}`); })(),
      writeFile: async () => {},
      home: "/tmp",
    });
    const push = async (...args: string[]) => {
      out.text = "";
      out.err = "";
      const code = await run(["directory", "push", "-c", "connector.yaml", ...args], io());
      return { code, ...out };
    };
    const setDisabled = async (uid: string, disabled: boolean) => {
      const c = new Client({ url: `ldaps://${HOST}:1636`, tlsOptions: { ca: [ca] } });
      await c.bind("cn=admin,dc=acme,dc=test", "admin-password");
      await c.modify(`uid=${uid},ou=people,dc=acme,dc=test`, new Change({ operation: disabled ? "add" : "delete", modification: new Attribute({ type: "employeeType", values: disabled ? ["disabled"] : [] }) }));
      await c.unbind();
    };

    beforeAll(async () => {
      await owner.query("DELETE FROM users WHERE email LIKE '%@acme.test'"); // the direct-sync org had them
      token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Push Co", email: uniqueEmail("push"), password: PASSWORD, given_name: "Root" } })).body.token;
      await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
      orgId = (await h.call("GET", "/v1/me", { token })).body.organization.id;
      const r = await h.call("POST", "/v1/directory/scim", { token, body: { name: "Corp AD (on-prem)", invite_new_users: false } });
      expect(r.status, JSON.stringify(r.body)).toBe(201);
      scimToken = r.body.scim.token;
      files.set("ca.pem", ca);
      files.set(
        "connector.yaml",
        [
          "scim:",
          `  url: ${r.body.scim.base_url}`,
          "  token_env: NEXUS_SCIM_TOKEN",
          "ldap:",
          "  preset: openldap",
          `  url: ldaps://${HOST}:1636`,
          "  ca_cert_file: ca.pem",
          "  bind_dn: cn=svc-nexus,ou=service,dc=acme,dc=test",
          "  bind_password_env: LDAP_BIND_PASSWORD",
          "  base_dn: dc=acme,dc=test",
          "  user_base_dn: ou=people,dc=acme,dc=test",
          '  disabled_filter: "(employeeType=disabled)"',
        ].join("\n"),
      );
    });
    afterAll(async () => {
      await setDisabled("bob", false).catch(() => {});
    });

    it("shows what it would do with --dry-run, and changes nothing", async () => {
      const r = await push("--dry-run");
      expect(r.code, r.err).toBe(0);
      expect(r.text).toMatch(/Would change:\n {2}create: 3/);
      expect(r.text).toContain("new groups: 3");
      expect((await h.call("GET", "/v1/users?q=acme.test", { token })).body.data).toEqual([]);
    });

    it("pushes people and nested groups over SCIM, then has nothing to do", async () => {
      const r = await push();
      expect(r.code, r.err).toBe(0);
      const users = (await h.call("GET", "/v1/users?q=acme.test", { token })).body.data;
      expect(users.map((u: any) => `${u.email}:${u.managed_by}`).sort()).toEqual(["alice@acme.test:SCIM", "bob@acme.test:SCIM", "carol@acme.test:SCIM"]);
      const eng = (await h.call("GET", "/v1/groups?q=engineering", { token })).body.data[0];
      expect(eng.member_count).toBe(2);
      expect((await push()).text).toBe("Nexus already matches the directory.\n");
    });

    it("deactivates someone disabled in the directory, and brings them back", async () => {
      await setDisabled("bob", true);
      expect((await push()).text).toMatch(/deactivate: 1 \(bob@acme.test\)/);
      const bob = async () => (await h.call("GET", "/v1/users?q=bob@acme.test", { token })).body.data[0].status;
      expect(await bob()).toBe("suspended");
      await setDisabled("bob", false);
      expect((await push()).text).toMatch(/reactivate: 1/);
      expect(await bob()).toBe("staged"); // back to where they were: never set up yet
      expect(orgId).toBeTruthy();
    });

    it("explains missing secrets", async () => {
      const bad = io();
      bad.env = {};
      out.err = "";
      expect(await run(["directory", "push", "-c", "connector.yaml"], bad)).toBe(1);
      expect(out.err).toContain("NEXUS_SCIM_TOKEN");
    });
  });
});

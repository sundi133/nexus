import { generateKeyPairSync } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { jwtVerify, importSPKI } from "jose";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/**
 * Directory sync (DIR-08) against fake Google Admin SDK and Microsoft Graph
 * servers that behave like the real ones: signed service-account assertions,
 * client-credential secrets, pagination, guests, suspended accounts.
 */

// ---- fake providers ----------------------------------------------------------------

type GUser = { id: string; primaryEmail: string; name: { givenName: string; familyName: string }; suspended?: boolean; organizations?: { title?: string; department?: string; primary?: boolean }[] };
const tag = Math.random().toString(36).slice(2, 8); // emails are unique across orgs: keep runs apart
const mail = (local: string) => `${local}-${tag}@acme.test`;
const google = {
  users: [] as GUser[],
  groups: [] as { id: string; name: string; description?: string; members: string[] }[],
  tokenStatus: 200,
};
const graph = {
  users: [] as Record<string, unknown>[],
  groups: [] as { id: string; displayName: string; members: string[] }[],
  poisonNextLink: false,
};
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const SA_EMAIL = "nexus-sync@acme-project.iam.gserviceaccount.com";
const ADMIN = "it-admin@acme.test";
const ENTRA_SECRET = "entra-secret-value";

let server: http.Server;
let base = "";

function page<T>(items: T[], token: string | null, size: number) {
  const start = Number(token ?? 0);
  const next = start + size < items.length ? String(start + size) : undefined;
  return { slice: items.slice(start, start + size), next };
}

async function handle(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url!, base);
  const body = await new Promise<string>((r) => {
    let d = "";
    req.on("data", (c) => (d += c)).on("end", () => r(d));
  });
  const send = (status: number, json: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(json));
  const auth = req.headers.authorization;

  if (url.pathname === "/google/token") {
    if (google.tokenStatus !== 200) return send(google.tokenStatus, { error: "unauthorized_client", error_description: "Client is unauthorized to retrieve access tokens using this method" });
    const assertion = new URLSearchParams(body).get("assertion")!;
    const { payload } = await jwtVerify(assertion, await importSPKI(publicKey.export({ type: "spki", format: "pem" }).toString(), "RS256"), { audience: `${base}/google/token`, issuer: SA_EMAIL });
    if (payload.sub !== ADMIN || !String(payload.scope).includes("admin.directory.user.readonly")) return send(403, { error: "access_denied" });
    return send(200, { access_token: "gtok", expires_in: 3600 });
  }
  if (url.pathname.startsWith("/google/admin/directory/v1/")) {
    if (auth !== "Bearer gtok") return send(401, { error: { message: "Invalid credentials" } });
    const rest = url.pathname.slice("/google/admin/directory/v1/".length);
    if (rest === "users") {
      const p = page(google.users, url.searchParams.get("pageToken"), 2);
      return send(200, { users: p.slice, nextPageToken: p.next });
    }
    if (rest === "groups") return send(200, { groups: google.groups.map(({ members: _m, ...g }) => g) });
    const m = /^groups\/([^/]+)\/members$/.exec(rest);
    if (m) return send(200, { members: google.groups.find((g) => g.id === decodeURIComponent(m[1]!))!.members.map((id) => ({ id, type: "USER" })) });
  }
  if (/^\/entra\/[^/]+\/oauth2\/v2.0\/token$/.test(url.pathname)) {
    const f = new URLSearchParams(body);
    if (f.get("client_secret") !== ENTRA_SECRET) return send(401, { error: "invalid_client", error_description: "AADSTS7000215: Invalid client secret provided." });
    return send(200, { access_token: "etok" });
  }
  if (url.pathname.startsWith("/graph/v1.0/")) {
    if (auth !== "Bearer etok") return send(401, { error: { message: "Unauthorized" } });
    const rest = url.pathname.slice("/graph/v1.0/".length);
    const skip = url.searchParams.get("$skiptoken");
    const nextLink = (next?: string) => (next ? (graph.poisonNextLink ? "http://169.254.169.254/latest/meta-data" : `${base}/graph/v1.0/${rest}?$skiptoken=${next}`) : undefined);
    if (rest === "users") {
      const p = page(graph.users, skip, 2);
      return send(200, { value: p.slice, "@odata.nextLink": nextLink(p.next) });
    }
    if (rest === "groups") return send(200, { value: graph.groups.map((g) => ({ id: g.id, displayName: g.displayName })) });
    const m = /^groups\/([^/]+)\/transitiveMembers\/microsoft.graph.user$/.exec(rest);
    if (m) return send(200, { value: graph.groups.find((g) => g.id === m[1])!.members.map((id) => ({ id })) });
  }
  send(404, { error: "not found" });
}

// ---- app ---------------------------------------------------------------------------

let h: Awaited<ReturnType<typeof bootApp>>;
let owner: pg.Client;
let admin = "";
let orgId = "";
let helpdesk = "";
const saKey = (over: Record<string, unknown> = {}) =>
  JSON.stringify({ type: "service_account", client_email: SA_EMAIL, private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(), token_uri: `${base}/google/token`, ...over });
const googleCreds = (over: Record<string, unknown> = {}) => ({ provider: "google", admin_email: ADMIN, service_account_key: saKey(), ...over });

const gu = (id: string, local: string, extra: Partial<GUser> = {}): GUser => ({ id, primaryEmail: mail(local), name: { givenName: local[0]!.toUpperCase() + local.slice(1), familyName: "Acme" }, ...extra });
const users = async () =>
  (await h.call("GET", "/v1/users?limit=200", { token: admin })).body.data as { id: string; email: string; status: string; title: string; given_name: string; managed_by: string | null }[];
const byEmail = async (local: string) => (await users()).find((u) => u.email === mail(local));
const conns = async () => (await h.call("GET", "/v1/directory/connections", { token: admin })).body.data;
const runJobs = () => h.jobs.runOnce({ orgId });

beforeAll(async () => {
  server = http.createServer((req, res) => void handle(req, res).catch((e) => res.writeHead(500).end(String(e))));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  h = await bootApp({ googleTokenUrl: `${base}/google/token`, googleAdminBase: `${base}/google`, entraLoginBase: `${base}/entra`, graphBase: `${base}/graph` });
  owner = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await owner.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Acme", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  orgId = (await h.call("GET", "/v1/me", { token: admin })).body.organization.id;
  const hd = uniqueEmail("hd");
  await h.call("POST", "/v1/users", { token: admin, body: { email: hd, given_name: "Hd", password: PASSWORD, roles: ["helpdesk"] } });
  helpdesk = (await h.call("POST", "/v1/auth/login", { body: { email: hd, password: PASSWORD } })).body.token;

  google.users = [
    gu("g-ann", "ann", { organizations: [{ title: "CFO", department: "Finance", primary: true }] }),
    gu("g-bob", "bob"),
    gu("g-cat", "cat"),
    gu("g-dan", "dan", { suspended: true }),
    gu("g-eve", "eve"),
  ];
  google.groups = [
    { id: "grp-eng", name: "Engineering", description: "Builds things", members: ["g-bob", "g-cat"] },
    { id: "grp-fin", name: "Finance", members: ["g-ann"] },
  ];
  // Bob already has a Nexus account: sync should adopt it, not duplicate it.
  await h.call("POST", "/v1/users", { token: admin, body: { email: mail("bob"), given_name: "Robert", password: PASSWORD } });
});
afterAll(async () => {
  server.close();
  await owner.end();
  await h.close();
});

describe("connecting a directory", () => {
  it("tests credentials before saving anything", async () => {
    const ok = await h.call("POST", "/v1/directory/test", { token: admin, body: googleCreds() });
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body).toEqual({ users: 5, active_users: 4, groups: [{ id: "grp-eng", name: "Engineering", members: 2 }, { id: "grp-fin", name: "Finance", members: 1 }] });

    expect((await h.call("POST", "/v1/directory/test", { token: admin, body: googleCreds({ service_account_key: "{}" }) })).body.code).toBe("invalid_key");
    const wrongAdmin = await h.call("POST", "/v1/directory/test", { token: admin, body: googleCreds({ admin_email: "nobody@acme.test" }) });
    expect(wrongAdmin).toMatchObject({ status: 422, body: { code: "directory_unreachable" } });
    // A key file can't point our server at another token endpoint.
    const ssrf = await h.call("POST", "/v1/directory/test", { token: admin, body: googleCreds({ service_account_key: saKey({ token_uri: "http://169.254.169.254/token" }) }) });
    expect(ssrf.status).toBe(422);
    expect(ssrf.body.title).toContain("Unexpected token_uri");
    expect((await h.call("POST", "/v1/directory/test", { token: helpdesk, body: googleCreds() })).status).toBe(403);
  });

  it("saves a connection switched off, without ever returning the secret", async () => {
    const r = await h.call("POST", "/v1/directory/connections", { token: admin, body: { ...googleCreds(), name: "Google Workspace" } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.data[0]).toMatchObject({ provider: "google", provider_name: "Google Workspace", account: ADMIN, enabled: false, last_status: "never", deprovision: "suspend", invite_new_users: true });
    expect(JSON.stringify(r.body)).not.toContain("PRIVATE KEY");
  });

  it("previews exactly what the first sync will do", async () => {
    const id = (await conns())[0].id;
    const p = await h.call("POST", `/v1/directory/connections/${id}/preview`, { token: admin, body: {} });
    expect(p.status, JSON.stringify(p.body)).toBe(200);
    expect(p.body.create_users.map((u: { email: string }) => u.email).sort()).toEqual([mail("ann"), mail("cat"), mail("eve")]); // dan is suspended upstream
    expect(p.body.link_users).toEqual([{ email: mail("bob") }]);
    expect(p.body.update_users).toEqual([{ email: mail("bob"), changes: { given_name: { from: "Robert", to: "Bob" }, family_name: { from: "", to: "Acme" } } }]);
    expect(p.body.groups).toEqual(expect.arrayContaining([{ name: "Engineering", action: "create", add: 0, remove: 0 }, { name: "Engineering", action: "members", add: 2, remove: 0 }]));
    expect(p.body.guard.tripped).toBe(false);
    expect((await byEmail("ann"))).toBeUndefined(); // preview changed nothing
  });
});

describe("syncing", () => {
  let id = "";
  beforeAll(async () => {
    id = (await conns())[0].id;
  });

  it("creates, adopts, groups and invites", async () => {
    const q = await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    expect(q.status).toBe(202);
    expect(q.body.data[0].syncing).toBe(true);
    await runJobs();
    const c = (await conns())[0];
    expect(c).toMatchObject({ last_status: "ok", syncing: false, linked_users: 4, linked_groups: 2 });
    expect(c.last_result.summary).toMatchObject({ create_users: 3, link_users: 1, suspend_users: 0 });

    expect(await byEmail("ann")).toMatchObject({ status: "staged", title: "CFO", given_name: "Ann", managed_by: "Google Workspace" });
    expect(await byEmail("bob")).toMatchObject({ status: "active", given_name: "Bob" });
    const invited = h.mailer.sent.filter((m) => m.to.endsWith(`-${tag}@acme.test`)).map((m) => m.to).sort();
    expect(invited).toEqual([mail("ann"), mail("cat"), mail("eve")]);
    expect(h.mailer.sent.find((m) => m.to === mail("ann"))!.text).toContain("Your IT team invited you");

    const groups = (await h.call("GET", "/v1/groups", { token: admin })).body.data;
    const eng = groups.find((g: { name: string }) => g.name === "Engineering");
    expect(eng).toMatchObject({ description: "Builds things", member_count: 2 });
    const audit = await h.call("GET", "/v1/audit/events?type=directory.synced", { token: admin });
    expect(audit.body.data[0]).toMatchObject({ actor: { display: "Google Workspace sync" }, target: { display: "Google Workspace" } });
  });

  it("is idempotent", async () => {
    const p = await h.call("POST", `/v1/directory/connections/${id}/preview`, { token: admin, body: {} });
    expect(Object.values(p.body.summary).every((n) => n === 0)).toBe(true);
  });

  it("follows upstream changes: attributes, suspensions, removals, group moves", async () => {
    const bob = (await byEmail("bob"))!;
    const bobSession = (await h.call("POST", "/v1/auth/login", { body: { email: mail("bob"), password: PASSWORD } })).body.token;
    google.users.find((u) => u.id === "g-ann")!.organizations = [{ title: "CEO", department: "Exec", primary: true }];
    google.users.find((u) => u.id === "g-bob")!.suspended = true;
    google.users = google.users.filter((u) => u.id !== "g-eve");
    google.groups.find((g) => g.id === "grp-eng")!.members = ["g-cat", "g-ann"];
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    await runJobs();

    expect(await byEmail("ann")).toMatchObject({ title: "CEO" });
    expect(await byEmail("bob")).toMatchObject({ status: "suspended" });
    expect(await byEmail("eve")).toMatchObject({ status: "suspended" });
    expect((await h.call("GET", "/v1/me", { token: bobSession })).status).toBe(401); // sessions revoked
    const audit = await h.call("GET", "/v1/audit/events?type=user.suspended", { token: admin });
    expect(audit.body.data.find((e: { target: { id: string } }) => e.target.id === bob.id)).toMatchObject({
      actor: { display: "Google Workspace sync" },
      details: { reason: "Suspended in Google Workspace", sessions_revoked: 1 },
    });
    const eng = (await h.call("GET", "/v1/groups", { token: admin })).body.data.find((g: { name: string }) => g.name === "Engineering");
    const members = (await h.call("GET", `/v1/groups/${eng.id}/members`, { token: admin })).body.data.map((m: { email: string }) => m.email).sort();
    expect(members).toEqual([mail("ann"), mail("cat")]);
  });

  it("reactivates only the people it suspended", async () => {
    const cat = (await byEmail("cat"))!;
    // An admin contains Cat; the directory still says she's active.
    await h.call("POST", `/v1/users/${cat.id}/contain`, { token: admin, body: {} });
    google.users.find((u) => u.id === "g-bob")!.suspended = false;
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    await runJobs();
    expect(await byEmail("bob")).toMatchObject({ status: "active" });
    expect(await byEmail("cat")).toMatchObject({ status: "suspended" }); // the admin's decision stands
  });

  it("holds a mass suspension for approval instead of locking people out", async () => {
    // Someone narrows the Google side to a single user: everyone else would be suspended.
    for (let i = 0; i < 8; i++) google.users.push(gu(`g-x${i}`, `x${i}`));
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    await runJobs();
    const keep = google.users;
    google.users = google.users.filter((u) => u.id === "g-ann");
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    await runJobs();

    const c = (await conns())[0];
    expect(c.last_status).toBe("needs_approval");
    expect(c.last_result.guard).toEqual({ tripped: true, suspensions: 9, threshold: 5 });
    expect(await byEmail("bob")).toMatchObject({ status: "active" }); // nothing changed
    const inbox = await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin });
    expect(inbox.body.data[0]).toMatchObject({ title: "Google Workspace sync wants to suspend 9 people", severity: "warning" });

    // Approving fewer than the plan needs doesn't apply it.
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: { approved_suspensions: 5 } });
    await runJobs();
    expect((await conns())[0].last_status).toBe("needs_approval");
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: { approved_suspensions: 9 } });
    await runJobs();
    expect((await conns())[0].last_status).toBe("ok");
    expect(await byEmail("bob")).toMatchObject({ status: "suspended" });
    const approvals = await h.call("GET", "/v1/audit/events?type=directory.mass_change_approved", { token: admin });
    expect(approvals.body.data[0].details).toEqual({ approved_suspensions: 9 });
    google.users = keep;
  });

  it("skips people whose email belongs to another organization", async () => {
    const outsider = uniqueEmail("taken");
    await h.call("POST", "/v1/signup", { body: { organization_name: "Elsewhere", email: outsider, password: PASSWORD, given_name: "O" } });
    google.users.push({ id: "g-out", primaryEmail: outsider, name: { givenName: "O", familyName: "X" } });
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    await runJobs();
    const c = (await conns())[0];
    expect(c.last_status).toBe("ok");
    expect(c.last_result.skipped).toContainEqual({ email: outsider, reason: "This email is already used by another Nexus organization" });
  });

  it("records permanent failures without retrying, and alerts once", async () => {
    google.tokenStatus = 401;
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    await runJobs();
    const c = (await conns())[0];
    expect(c).toMatchObject({ last_status: "error", syncing: false });
    expect(c.last_error).toContain("Google sign-in failed (HTTP 401)");
    const inbox = await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: admin });
    expect(inbox.body.data[0].title).toBe("Google Workspace sync is failing");
    google.tokenStatus = 200;
  });

  it("is scheduled once enabled", async () => {
    await h.call("PATCH", `/v1/directory/connections/${id}`, { token: admin, body: { enabled: true, interval_minutes: 15 } });
    await owner.query("UPDATE directory_connections SET last_sync_at = now() - interval '20 minutes' WHERE id = $1", [id]);
    const due = await owner.query("SELECT connection_id FROM nexus_due_directory_syncs() WHERE org_id = $1", [orgId]);
    expect(due.rows).toEqual([{ connection_id: id }]);
    await owner.query("UPDATE directory_connections SET last_sync_at = now() WHERE id = $1", [id]);
    expect((await owner.query("SELECT 1 FROM nexus_due_directory_syncs() WHERE org_id = $1", [orgId])).rowCount).toBe(0);
  });
});

describe("Microsoft Entra ID", () => {
  let id = "";
  const TENANT = "0b1f7c3e-5a2d-4c6b-9e8f-1a2b3c4d5e6f";

  it("syncs members (not guests), following Graph pagination", async () => {
    graph.users = [
      { id: "e1", givenName: "Fay", surname: "Ent", mail: mail("fay"), userPrincipalName: mail("fay"), accountEnabled: true, jobTitle: "SRE", userType: "Member" },
      { id: "e2", givenName: "Gus", surname: "Ent", mail: null, userPrincipalName: mail("gus"), accountEnabled: true, userType: "Member" },
      { id: "e3", givenName: "Hal", surname: "Ext", mail: "hal@partner.test", userPrincipalName: "hal_partner.test#EXT#@acme.onmicrosoft.com", accountEnabled: true, userType: "Guest" },
    ];
    graph.groups = [{ id: "eg1", displayName: "SRE", members: ["e1", "e3"] }];
    const bad = await h.call("POST", "/v1/directory/test", { token: admin, body: { provider: "entra", tenant_id: TENANT, client_id: "5f7c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f", client_secret: "wrong" } });
    expect(bad.status).toBe(422);
    expect(bad.body.title).toContain("Invalid client secret");

    const r = await h.call("POST", "/v1/directory/connections", {
      token: admin,
      body: { provider: "entra", name: "Entra", tenant_id: TENANT, client_id: "5f7c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e5f", client_secret: ENTRA_SECRET, invite_new_users: false },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    id = r.body.data.find((c: { name: string }) => c.name === "Entra").id;
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    await runJobs();
    const c = (await conns()).find((x: { id: string }) => x.id === id);
    expect(c, JSON.stringify(c)).toMatchObject({ last_status: "ok", linked_users: 2, linked_groups: 1 });
    expect(await byEmail("fay")).toMatchObject({ title: "SRE", status: "staged" });
    expect(await byEmail("gus")).toBeDefined(); // UPN used when mail is empty
    expect((await users()).some((u) => u.email === "hal@partner.test")).toBe(false);
    expect(h.mailer.sent.some((m) => m.to === mail("fay"))).toBe(false); // invites off
  });

  it("refuses to follow a next-page link off Microsoft Graph", async () => {
    graph.poisonNextLink = true;
    await h.call("POST", `/v1/directory/connections/${id}/sync`, { token: admin, body: {} });
    await runJobs();
    const c = (await conns()).find((x: { id: string }) => x.id === id);
    expect(c.last_status).toBe("error");
    expect(c.last_error).toContain("unexpected next page URL");
    graph.poisonNextLink = false;
  });

  it("leaves people and groups in place when disconnected", async () => {
    const r = await h.call("DELETE", `/v1/directory/connections/${id}`, { token: admin });
    expect(r.status).toBe(200);
    expect(await byEmail("fay")).toMatchObject({ managed_by: null });
  });
});

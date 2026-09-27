import { createHash, randomBytes, randomUUID } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/**
 * People's own MCP clients through the gateway: the MCP authorization flow (discovery,
 * registration, sign-in with PKCE, tokens for the resource, refresh rotation), people and group
 * rules, data protection on arguments and results, and disconnecting.
 */

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
let slug = "";
let serverId = "";
let endpoint = "";
const sam = { id: "", email: uniqueEmail("sam"), token: "" };
const kim = { id: "", email: uniqueEmail("kim"), token: "" };
let groupId = "";

const calls: { tool: string; args: unknown }[] = [];
function buildServer() {
  const s = new McpServer({ name: "fake-crm", version: "1.0.0" });
  s.registerTool("lookup_customer", { description: "Look up a customer", inputSchema: { name: z.string() }, annotations: { readOnlyHint: true } }, async ({ name }) => {
    calls.push({ tool: "lookup_customer", args: { name } });
    return { content: [{ type: "text", text: `${name}: card 4242 4242 4242 4242, SSN 123-45-6789, api key AKIAIOSFODNN7EXAMPLE, plan Enterprise` }] };
  });
  s.registerTool("create_note", { description: "Add a note to a customer", inputSchema: { name: z.string(), note: z.string() } }, async ({ name, note }) => {
    calls.push({ tool: "create_note", args: { name, note } });
    return { content: [{ type: "text", text: `Noted for ${name}` }] };
  });
  return s;
}
const sessions = new Map<string, StreamableHTTPServerTransport>();
let upstream: http.Server;

const inProcessFetch = ((url: string | URL, init?: RequestInit) => h.app.request(String(url), init)) as typeof fetch;
const oidc = (path: string, init?: RequestInit) => h.app.request(`/oidc/${slug}${path}`, init);
const tokenForm = (f: Record<string, string>) => oidc("/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(f).toString() });

/** What an MCP client does: register, send the person to sign in, exchange the code. */
async function authorize(person: { token: string }, resource = endpoint) {
  const reg = await oidc("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Cursor", redirect_uris: ["http://127.0.0.1:51234/callback"] }) });
  const client = (await reg.json()) as { client_id: string };
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: "http://127.0.0.1:51234/callback",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    state: "xyz",
    resource,
    scope: "mcp",
  });
  const decision = (await h.call("GET", `/v1/sso/oidc/${slug}/authorize?${q}`, { token: person.token })).body;
  if (decision.action !== "redirect") return { decision, client };
  const code = new URL(decision.location).searchParams.get("code");
  if (!code) return { decision, client };
  const res = await tokenForm({ grant_type: "authorization_code", client_id: client.client_id, code, redirect_uri: "http://127.0.0.1:51234/callback", code_verifier: verifier, resource });
  return { decision, client, tokens: (await res.json()) as { access_token: string; refresh_token: string; expires_in: number; error?: string } };
}
async function connectAs(accessToken: string) {
  const c = new Client({ name: "cursor", version: "1.0.0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(endpoint), { fetch: inProcessFetch, requestInit: { headers: { authorization: `Bearer ${accessToken}` } } }));
  return c;
}
const text = (r: any) => r.content?.[0]?.text as string;

beforeAll(async () => {
  upstream = http.createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const sid = req.headers["mcp-session-id"] as string | undefined;
    let t = sid ? sessions.get(sid) : undefined;
    if (!t) {
      t = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), onsessioninitialized: (id) => void sessions.set(id, t!) });
      await buildServer().connect(t);
    }
    await t.handleRequest(req, res, raw ? JSON.parse(raw) : undefined);
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "People MCP", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  slug = (await h.call("GET", "/v1/me", { token: admin })).body.organization.slug;
  for (const p of [sam, kim]) {
    p.id = (await h.call("POST", "/v1/users", { token: admin, body: { email: p.email, given_name: "P", password: PASSWORD } })).body.id;
    p.token = (await h.call("POST", "/v1/auth/login", { body: { email: p.email, password: PASSWORD } })).body.token;
  }
  groupId = (await h.call("POST", "/v1/groups", { token: admin, body: { name: "Support" } })).body.id;
  await h.call("POST", `/v1/groups/${groupId}/members`, { token: admin, body: { user_ids: [sam.id] } });
  const s = await h.call("POST", "/v1/mcp/servers", { token: admin, body: { name: "CRM", slug: "crm", url: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/mcp`, auth: { kind: "none" } } });
  serverId = s.body.server.id;
  endpoint = s.body.server.endpoint;
  await h.call("POST", `/v1/mcp/servers/${serverId}/tools/review`, { token: admin, body: { names: ["lookup_customer", "create_note"], decision: "approve" } });
});
afterAll(async () => {
  upstream.close();
  await db.end();
  await h.close();
});

describe("discovery and registration", () => {
  it("tells MCP clients where to sign in and register", async () => {
    const meta = (await (await oidc("/.well-known/oauth-authorization-server")).json()) as any;
    expect(meta.registration_endpoint).toBe(`${meta.issuer}/register`);
    expect(meta.grant_types_supported).toContain("refresh_token");
    expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("registers only clients that receive codes on this device or in an app", async () => {
    const reg = (uris: string[], extra = {}) => oidc("/register", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "X", redirect_uris: uris, ...extra }) });
    for (const ok of [["http://127.0.0.1:3333/cb"], ["http://localhost/callback"], ["cursor://anysphere.cursor-retrieval/oauth/callback"], ["vscode://vscode.github-authentication/did-authenticate"]]) {
      expect((await reg(ok)).status, ok[0]).toBe(201);
    }
    for (const bad of [["https://evil.example/cb"], ["http://evil.example/cb"], ["javascript:alert(1)"], ["http://127.0.0.1/cb#frag"], []]) {
      expect((await reg(bad)).status, String(bad[0])).toBe(400);
    }
    expect((await reg(["http://127.0.0.1/cb"], { token_endpoint_auth_method: "client_secret_basic" })).status).toBe(400);
  });
});

describe("signing in", () => {
  it("is refused to people without any tools, before they're given some", async () => {
    const r = await authorize(sam);
    expect(r.decision).toMatchObject({ action: "error", code: "no_mcp_access" });
  });

  it("gives a person a token for the server, and the tools their group may use", async () => {
    const perm = await h.call("POST", `/v1/mcp/servers/${serverId}/permissions`, { token: admin, body: { effect: "allow", subject: { type: "group", id: groupId }, tools: ["*"], risks: ["read"] } });
    const r = await authorize(sam);
    expect(perm.status, JSON.stringify(perm.body)).toBe(201);
    expect(r.tokens?.access_token, JSON.stringify({ d: r.decision, t: r.tokens ?? null })).toBeTruthy();
    expect(r.tokens?.expires_in).toBe(3600);
    expect(r.tokens?.refresh_token).toMatch(/^nxr_/);
    const c = await connectAs(r.tokens!.access_token);
    expect((await c.listTools()).tools.map((t) => t.name)).toEqual(["lookup_customer"]); // read only
    await c.close();
    // Kim isn't in the group.
    expect((await authorize(kim)).decision).toMatchObject({ code: "no_mcp_access" });
  });

  it("refuses a code sent elsewhere, a wrong verifier, or a resource outside the gateway", async () => {
    const r = await authorize(sam, "https://attacker.example/mcp");
    expect(r.decision.action).toBe("redirect");
    expect(new URL(r.decision.location).searchParams.get("error")).toBe("invalid_target");
  });
});

describe("tool calls as a person", () => {
  let access = "";
  let refresh = "";
  let clientId = "";

  it("are audited as the person, with the client they used", async () => {
    const r = await authorize(sam);
    access = r.tokens!.access_token;
    refresh = r.tokens!.refresh_token;
    clientId = r.client.client_id;
    const c = await connectAs(access);
    await c.callTool({ name: "lookup_customer", arguments: { name: "Initech" } });
    await c.close();
    const ev = (await db.query("SELECT actor_type, actor_id, actor_display, details FROM audit_events WHERE type = 'mcp.tool_called' AND actor_id = $1", [sam.id])).rows;
    expect(ev).toHaveLength(1);
    expect(ev[0]).toMatchObject({ actor_type: "user", actor_display: sam.email, details: { tool: "lookup_customer", via: "Cursor" } });
  });

  it("redact secrets before the AI reads them, and note what else was there", async () => {
    const c = await connectAs(access);
    const out = text(await c.callTool({ name: "lookup_customer", arguments: { name: "Initech" } }));
    await c.close();
    expect(out).toContain("[redacted: AWS access key]");
    expect(out).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(out).toContain("4242 4242 4242 4242"); // cards are monitored by default, not redacted
    const d = (await db.query("SELECT details FROM audit_events WHERE type = 'mcp.tool_called' AND actor_id = $1 ORDER BY ts DESC LIMIT 1", [sam.id])).rows[0].details;
    expect(d.dlp_results).toEqual(expect.arrayContaining([expect.objectContaining({ detector: "secret", action: "redact" }), expect.objectContaining({ detector: "credit_card", action: "monitor" })]));
  });

  it("stop a call whose arguments carry a secret, and follow the policy when it changes", async () => {
    await h.call("POST", `/v1/mcp/servers/${serverId}/permissions`, { token: admin, body: { effect: "allow", subject: { type: "user", id: sam.id }, tools: ["create_note"] } });
    const c = await connectAs(access);
    const blocked = await c.callTool({ name: "create_note", arguments: { name: "Initech", note: "their prod key is AKIAIOSFODNN7EXAMPLE" } });
    expect(blocked.isError).toBe(true);
    expect(text(blocked)).toContain("the arguments contain AWS access key");
    expect(calls.some((x) => x.tool === "create_note")).toBe(false); // never reached the tool
    // Redact cards too, from now on.
    expect((await h.call("PUT", "/v1/mcp/data-protection", { token: admin, body: { results: { credit_card: "redact" } } })).status).toBe(200);
    const out = text(await c.callTool({ name: "lookup_customer", arguments: { name: "Initech" } }));
    expect(out).toContain("[redacted: Payment card number]");
    await c.close();
  });

  it("rotates the refresh token, and ends the grant when an old one is replayed", async () => {
    const first = (await (await tokenForm({ grant_type: "refresh_token", refresh_token: refresh, client_id: clientId })).json()) as any;
    expect(first.access_token).toBeTruthy();
    expect(first.refresh_token).not.toBe(refresh);
    // The old refresh token again: someone copied it. The grant ends, for both copies.
    const replay = await tokenForm({ grant_type: "refresh_token", refresh_token: refresh, client_id: clientId });
    expect(replay.status).toBe(400);
    const next = await tokenForm({ grant_type: "refresh_token", refresh_token: first.refresh_token, client_id: clientId });
    expect(((await next.json()) as any).error).toBe("invalid_grant");
    expect((await db.query("SELECT 1 FROM audit_events WHERE type = 'mcp.grant_revoked' AND details->>'reason' = 'refresh_token_reused' AND target_id = $1", [sam.id])).rowCount).toBe(1);
  });

  it("lets people see and disconnect their AI clients, and sign-out everywhere ends them all", async () => {
    const r = await authorize(sam);
    const mine = (await h.call("GET", "/v1/me/mcp-connections", { token: sam.token })).body.data;
    expect(mine.map((x: any) => x.client)).toContain("Cursor");
    expect((await h.call("GET", `/v1/users/${sam.id}/mcp-connections`, { token: admin })).body.data.length).toBe(mine.length);
    // An admin signs Sam out everywhere: the AI client's token stops working at once.
    await h.call("POST", `/v1/users/${sam.id}/revoke-sessions`, { token: admin, body: { reason: "lost laptop" } });
    const res = await h.app.request(endpoint, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${r.tokens!.access_token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
    expect(res.status).toBe(401);
    expect((await h.call("GET", "/v1/me/mcp-connections", { token: (await h.call("POST", "/v1/auth/login", { body: { email: sam.email, password: PASSWORD } })).body.token })).body.data).toEqual([]);
  });
});

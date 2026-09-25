import http from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { verifyAgentToken } from "../src/ai-agents/tokens.js";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** AI agent identities (AGT-01/02/03/06/07): registry, credentials, tokens, kill switch, owners. */

let h: Awaited<ReturnType<typeof bootApp>>;
let token = "";
let orgId = "";
let slug = "";
let issuer = "";
let gateway = "";
let ownerId = "";
let agentId = "";
let clientId = "";

// A workload identity provider (like GitHub Actions): discovery + JWKS on localhost.
let wip: http.Server;
let wipIssuer = "";
const wipKeys = await generateKeyPair("RS256");

const form = (f: Record<string, string>, basic?: [string, string]) =>
  h.app.request(`/oidc/${slug}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...(basic ? { authorization: `Basic ${Buffer.from(`${basic[0]}:${basic[1]}`).toString("base64")}` } : {}) },
    body: new URLSearchParams(f).toString(),
  });
const tokenJson = async (res: Response) => ({ status: res.status, body: (await res.json()) as any });
const verify = (t: string, serverUrl = `${gateway}/github`) => h.deps.db.tenant(orgId, (tx) => verifyAgentToken(tx, h.deps, orgId, { token: t, issuer, slug, serverUrl }));

beforeAll(async () => {
  h = await bootApp();
  const email = uniqueEmail("root");
  token = (await h.call("POST", "/v1/signup", { body: { organization_name: "Agent Co", email, password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token, body: { mfa_policy: "off" } });
  const me = (await h.call("GET", "/v1/me", { token })).body;
  orgId = me.organization.id;
  slug = me.organization.slug;
  ownerId = (await h.call("POST", "/v1/users", { token, body: { email: uniqueEmail("owner"), given_name: "Olive", password: PASSWORD } })).body.id;

  const pub = { ...(await exportJWK(wipKeys.publicKey)), kid: "wip1", alg: "RS256", use: "sig" };
  wip = http.createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url === "/.well-known/openid-configuration") res.end(JSON.stringify({ issuer: wipIssuer, jwks_uri: `${wipIssuer}/jwks` }));
    else if (req.url === "/jwks") res.end(JSON.stringify({ keys: [pub] }));
    else res.writeHead(404).end("{}");
  });
  await new Promise<void>((r) => wip.listen(0, "127.0.0.1", r));
  wipIssuer = `http://127.0.0.1:${(wip.address() as AddressInfo).port}`;
});
afterAll(async () => {
  wip.close();
  await h.close();
});

describe("registry", () => {
  it("registers an agent with an owner", async () => {
    expect((await h.call("POST", "/v1/agents", { token, body: { name: "Support bot" } })).body.code).toBe("owner_required");
    const r = await h.call("POST", "/v1/agents", { token, body: { name: "Support bot", owner_user_id: ownerId, runtime: "Claude Agent SDK", model: "claude-sonnet-5", risk_tier: "high", tags: ["support", "tier1"] } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    agentId = r.body.id;
    clientId = r.body.client_id;
    expect(r.body).toMatchObject({ owner: { type: "user", id: ownerId, active: true }, status: "active", token_ttl_minutes: 15, stale: false, credentials: 0 });
    expect(clientId).toMatch(/^agt_/);
    const list = (await h.call("GET", "/v1/agents?q=support", { token })).body;
    expect(list.data.map((a: any) => a.id)).toEqual([agentId]);
    expect(list.endpoints).toMatchObject({ token_endpoint: `${list.endpoints.issuer}/token` });
    issuer = list.endpoints.issuer;
    gateway = list.endpoints.gateway;
  });

  it("advertises client_credentials and private_key_jwt", async () => {
    const d = (await (await h.app.request(`/oidc/${slug}/.well-known/openid-configuration`)).json()) as any;
    expect(d.grant_types_supported).toContain("client_credentials");
    expect(d.token_endpoint_auth_methods_supported).toContain("private_key_jwt");
  });
});

describe("credentials and tokens", () => {
  let secret = "";
  it("issues short-lived, gateway-bound tokens for a client secret", async () => {
    const r = await h.call("POST", `/v1/agents/${agentId}/credentials`, { token, body: { kind: "secret", name: "prod" } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    secret = r.body.secret;
    expect(r.body.credential).toMatchObject({ kind: "secret", hint: secret.slice(-4) });
    const t = await tokenJson(await form({ grant_type: "client_credentials" }, [clientId, secret]));
    expect(t.status, JSON.stringify(t.body)).toBe(200);
    expect(t.body).toMatchObject({ token_type: "Bearer", expires_in: 900, scope: "mcp" });
    expect(await verify(t.body.access_token)).toMatchObject({ agentId, name: "Support bot", tags: ["support", "tier1"] });
    expect((await tokenJson(await form({ grant_type: "client_credentials", client_id: clientId, client_secret: "agts_wrong" }))).status).toBe(401);
    const ev = (await h.call("GET", `/v1/audit/events?type=agent.token_issued`, { token })).body.data[0];
    expect(ev).toMatchObject({ actor: { type: "agent", id: agentId }, details: { credential: "secret", expires_in: 900 } });
  });

  it("binds tokens to one server when asked (RFC 8707)", async () => {
    const t = (await tokenJson(await form({ grant_type: "client_credentials", resource: `${gateway}/github` }, [clientId, secret]))).body.access_token;
    expect(await verify(t, `${gateway}/github`)).toMatchObject({ agentId });
    expect(await verify(t, `${gateway}/jira`)).toMatchObject({ error: expect.stringContaining("invalid") });
    expect((await tokenJson(await form({ grant_type: "client_credentials", resource: "https://evil.example/mcp" }, [clientId, secret]))).body.error).toBe("invalid_target");
  });

  it("accepts a private_key_jwt once, and refuses private keys at registration", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const priv = await exportJWK(privateKey);
    expect((await h.call("POST", `/v1/agents/${agentId}/credentials`, { token, body: { kind: "public_key", jwk: priv } })).body.code).toBe("private_key");
    const r = await h.call("POST", `/v1/agents/${agentId}/credentials`, { token, body: { kind: "public_key", name: "laptop", jwk: { ...(await exportJWK(publicKey)), kid: "k1" } } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const assertion = await new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: "k1" }).setIssuer(clientId).setSubject(clientId).setAudience(`${issuer}/token`).setJti("a-1").setIssuedAt().setExpirationTime("2m").sign(privateKey);
    const f = { grant_type: "client_credentials", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion };
    const t = await tokenJson(await form(f));
    expect(t.status, JSON.stringify(t.body)).toBe(200);
    expect((await tokenJson(await form(f))).body.error_description).toContain("already used");
    const long = await new SignJWT({}).setProtectedHeader({ alg: "ES256" }).setIssuer(clientId).setSubject(clientId).setAudience(`${issuer}/token`).setJti("a-2").setExpirationTime("1h").sign(privateKey);
    expect((await tokenJson(await form({ ...f, client_assertion: long }))).body.error_description).toContain("10 minutes");
  });

  it("trusts a workload identity token for an exact subject, with no secret", async () => {
    const sub = "repo:acme/support-bot:ref:refs/heads/main";
    const r = await h.call("POST", `/v1/agents/${agentId}/credentials`, { token, body: { kind: "federated", name: "GitHub Actions", issuer: wipIssuer, subject: sub } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.credential).toMatchObject({ issuer: wipIssuer, subject: sub, audience: issuer });
    const wt = (s: string, aud = issuer) => new SignJWT({ repository: "acme/support-bot" }).setProtectedHeader({ alg: "RS256", kid: "wip1" }).setIssuer(wipIssuer).setSubject(s).setAudience(aud).setIssuedAt().setExpirationTime("5m").sign(wipKeys.privateKey);
    const f = (a: string) => ({ grant_type: "client_credentials", client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: a });
    const ok = await tokenJson(await form(f(await wt(sub))));
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect((await tokenJson(await form(f(await wt("repo:acme/support-bot:ref:refs/heads/evil"))))).status).toBe(401);
    expect((await tokenJson(await form(f(await wt(sub, "someone-else"))))).status).toBe(401);
    const ev = (await h.call("GET", `/v1/audit/events?type=agent.token_issued`, { token })).body.data[0];
    expect(ev.details).toMatchObject({ credential: "federated", workload: sub });
  });

  it("stops issuing for a revoked credential", async () => {
    const creds = (await h.call("GET", `/v1/agents/${agentId}`, { token })).body.credentials;
    const s = creds.find((c: any) => c.kind === "secret");
    expect(s.last_used_at).toBeTruthy();
    expect((await h.call("DELETE", `/v1/agents/${agentId}/credentials/${s.id}`, { token })).status).toBe(204);
    expect((await tokenJson(await form({ grant_type: "client_credentials" }, [clientId, secret]))).status).toBe(401);
    // Re-issue one for the next tests.
    secret = (await h.call("POST", `/v1/agents/${agentId}/credentials`, { token, body: { kind: "secret" } })).body.secret;
  });

  describe("kill switch", () => {
    it("invalidates every token at once, and blocks new ones", async () => {
      const t = (await tokenJson(await form({ grant_type: "client_credentials" }, [clientId, secret]))).body.access_token;
      expect(await verify(t)).toMatchObject({ agentId });
      const r = await h.call("POST", `/v1/agents/${agentId}/suspend`, { token, body: { reason: "Leaked prompt injection" } });
      expect(r.body).toMatchObject({ status: "suspended", status_reason: "Leaked prompt injection" });
      expect(await verify(t)).toMatchObject({ error: "This agent is suspended" });
      expect((await tokenJson(await form({ grant_type: "client_credentials" }, [clientId, secret]))).body.error_description).toBe("This agent is suspended");
      const inbox = (await h.call("POST", "/v1/auth/login", { body: { email: (await h.call("GET", `/v1/users/${ownerId}`, { token })).body.email, password: PASSWORD } })).body.token;
      expect((await h.call("GET", "/v1/me/notifications?limit=5&filter=all", { token: inbox })).body.data[0].title).toBe("Your agent Support bot was suspended");
    });

    it("keeps old tokens dead after reactivation", async () => {
      const before = (await tokenJson(await form({ grant_type: "client_credentials" }, [clientId, secret]))).status;
      expect(before).toBe(400);
      await h.call("POST", `/v1/agents/${agentId}/activate`, { token, body: {} });
      await new Promise((r) => setTimeout(r, 1100)); // tokens from the kill switch's second are refused too
      const t = (await tokenJson(await form({ grant_type: "client_credentials" }, [clientId, secret]))).body.access_token;
      expect(await verify(t)).toMatchObject({ agentId });
    });
  });
});

describe("owners", () => {
  it("suspends an owner's agents when they're offboarded, until reassigned", async () => {
    expect((await h.call("GET", `/v1/users/${ownerId}/offboarding`, { token })).body.agents).toEqual([{ id: agentId, name: "Support bot" }]);
    const r = await h.call("POST", `/v1/users/${ownerId}/offboard`, { token, body: { reason: "left" } });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const ev = (await h.call("GET", "/v1/audit/events?type=user.offboarded", { token })).body.data[0];
    expect(ev.details.effects.agents_suspended).toEqual(["Support bot"]);
    const a = (await h.call("GET", `/v1/agents/${agentId}`, { token })).body.agent;
    expect(a).toMatchObject({ status: "suspended", owner: { active: false } });
    expect((await h.call("POST", `/v1/agents/${agentId}/activate`, { token, body: {} })).body.code).toBe("owner_required");
    const me = (await h.call("GET", "/v1/me", { token })).body.user.id;
    await h.call("PATCH", `/v1/agents/${agentId}`, { token, body: { owner_user_id: me } });
    expect((await h.call("POST", `/v1/agents/${agentId}/activate`, { token, body: {} })).body.status).toBe("active");
  });

  it("suspends a contained owner's agents", async () => {
    const u = (await h.call("POST", "/v1/users", { token, body: { email: uniqueEmail("dev"), given_name: "Dev", password: PASSWORD } })).body.id;
    await h.call("POST", "/v1/agents", { token, body: { name: "Deploy bot", owner_user_id: u } });
    const r = await h.call("POST", `/v1/users/${u}/contain`, { token, body: { reason: "phished" } });
    expect(r.body.effects.agents_suspended).toEqual(["Deploy bot"]);
  });

  it("lets only admins manage agents, and analysts pull the kill switch", async () => {
    const email = uniqueEmail("analyst");
    await h.call("POST", "/v1/users", { token, body: { email, given_name: "Ana", password: PASSWORD, roles: ["security_analyst"] } });
    const t = (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token;
    expect((await h.call("POST", "/v1/agents", { token: t, body: { name: "x", owner_user_id: ownerId } })).status).toBe(403);
    expect((await h.call("POST", `/v1/agents/${agentId}/suspend`, { token: t, body: {} })).status).toBe(200);
  });
});

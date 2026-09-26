import * as oidc from "openid-client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/**
 * Drives our OIDC provider with openid-client (a certified relying-party
 * library) so discovery, ID token signatures, iss/aud/nonce/at_hash and PKCE
 * are validated by an independent implementation, not by our own assertions.
 */

let h: Awaited<ReturnType<typeof bootApp>>;
let admin = "";
let slug = "";
let aliceId = "";
let alice = ""; // alice's session token
const aliceEmail = uniqueEmail("alice");
const REDIRECT = "https://wiki.example.com/oauth/callback";
const WEB = "http://localhost:3100";

/** Route the relying party's HTTP calls to the in-process app (the web tier proxies /oidc/* the same way). */
const rpFetch: oidc.CustomFetch = async (url, options) => {
  const u = new URL(url);
  const res = await h.app.request(u.pathname + u.search, {
    method: options.method,
    headers: options.headers as RequestInit["headers"],
    body: options.body as RequestInit["body"],
  });
  return res;
};

async function relyingParty(clientId: string, secret: string | null) {
  const config = await oidc.discovery(
    new URL(`${WEB}/oidc/${slug}`),
    clientId,
    undefined,
    secret ? oidc.ClientSecretBasic(secret) : oidc.None(),
    { execute: [oidc.allowInsecureRequests], [oidc.customFetch]: rpFetch },
  );
  config[oidc.customFetch] = rpFetch;
  return config;
}

/** What the console's /oidc/{slug}/authorize handler does: ask the API for a decision with the user's session. */
async function authorize(url: URL, token?: string) {
  const r = await h.call("GET", `/v1/sso/oidc/${slug}/authorize${url.search}`, { token });
  expect(r.status).toBe(200);
  return r.body as { action: string; location?: string; code?: string; title?: string };
}

async function createApp(body: Record<string, unknown>) {
  const r = await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "oidc", ...body } });
  expect(r.status, JSON.stringify(r.body)).toBe(201);
  return r.body as { app: { id: string; oidc: { client_id: string; issuer: string; discovery_url: string } }; client_secret: string | null };
}

beforeAll(async () => {
  h = await bootApp();
  const org = await h.call("POST", "/v1/signup", { body: { organization_name: "Pied Piper", email: uniqueEmail("richard"), password: PASSWORD, given_name: "Richard" } });
  admin = org.body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  slug = (await h.call("GET", "/v1/me", { token: admin })).body.organization.slug;
  const u = await h.call("POST", "/v1/users", { token: admin, body: { email: aliceEmail, given_name: "Alice", family_name: "Liddell", password: PASSWORD } });
  aliceId = u.body.id;
  alice = (await h.call("POST", "/v1/auth/login", { body: { email: aliceEmail, password: PASSWORD } })).body.token;
});
afterAll(() => h.close());

describe("OIDC provider", () => {
  let app: Awaited<ReturnType<typeof createApp>>;

  it("creates an app and shows the secret once", async () => {
    app = await createApp({ name: "Team Wiki", redirect_uris: [REDIRECT], launch_url: "https://wiki.example.com/login" });
    expect(app.client_secret).toMatch(/^nxcs_/);
    expect(app.app.oidc.issuer).toBe(`${WEB}/oidc/${slug}`);
    const again = await h.call("GET", `/v1/apps/${app.app.id}`, { token: admin });
    expect(JSON.stringify(again.body)).not.toContain(app.client_secret!);
  });

  it("refuses insecure redirect URIs", async () => {
    const r = await h.call("POST", "/v1/apps", { token: admin, body: { protocol: "oidc", name: "Bad", redirect_uris: ["http://evil.example.com/cb"] } });
    expect(r.status).toBe(400);
  });

  it("publishes discovery and JWKS", async () => {
    const d = await h.app.request(`/oidc/${slug}/.well-known/openid-configuration`);
    const doc = (await d.json()) as Record<string, unknown>;
    expect(doc).toMatchObject({ issuer: `${WEB}/oidc/${slug}`, code_challenge_methods_supported: ["S256"], id_token_signing_alg_values_supported: ["RS256"] });
    const jwks = (await (await h.app.request(`/oidc/${slug}/jwks`)).json()) as { keys: Record<string, unknown>[] };
    expect(jwks.keys[0]).toMatchObject({ kty: "RSA", alg: "RS256", use: "sig" });
    expect(jwks.keys[0]).not.toHaveProperty("d"); // never the private part
  });

  it("does not let unassigned users in", async () => {
    const rp = await relyingParty(app.app.oidc.client_id, app.client_secret);
    const url = oidc.buildAuthorizationUrl(rp, { redirect_uri: REDIRECT, scope: "openid email", state: "s1", code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: "S256" });
    const d = await authorize(url, alice);
    expect(d).toMatchObject({ action: "error", code: "not_assigned" });
  });

  it("signs an assigned user in: a certified RP validates the whole flow", async () => {
    const group = await h.call("POST", "/v1/groups", { token: admin, body: { name: "Wiki users" } });
    await h.call("POST", `/v1/groups/${group.body.id}/members`, { token: admin, body: { user_ids: [aliceId] } });
    expect((await h.call("POST", `/v1/apps/${app.app.id}/assignments`, { token: admin, body: { principals: [{ type: "group", id: group.body.id }] } })).status).toBe(204);

    const rp = await relyingParty(app.app.oidc.client_id, app.client_secret);
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const url = oidc.buildAuthorizationUrl(rp, {
      redirect_uri: REDIRECT,
      scope: "openid email profile groups",
      state,
      nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: "S256",
    });
    const d = await authorize(url, alice);
    expect(d.action).toBe("redirect");
    const callback = new URL(d.location!);
    expect(callback.origin + callback.pathname).toBe(REDIRECT);
    expect(callback.searchParams.get("iss")).toBe(`${WEB}/oidc/${slug}`);

    const tokens = await oidc.authorizationCodeGrant(rp, callback, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
    const claims = tokens.claims()!;
    expect(claims).toMatchObject({
      sub: aliceId,
      email: aliceEmail,
      email_verified: true,
      name: "Alice Liddell",
      groups: ["Wiki users"],
      aud: app.app.oidc.client_id,
    });
    const info = await oidc.fetchUserInfo(rp, tokens.access_token, aliceId);
    expect(info).toMatchObject({ sub: aliceId, email: aliceEmail });

    // The same code can't be redeemed twice.
    await expect(oidc.authorizationCodeGrant(rp, callback, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce })).rejects.toMatchObject({ error: "invalid_grant" });

    const audit = await h.call("GET", "/v1/audit/events?type=sso.login", { token: admin });
    expect(audit.body.data[0]).toMatchObject({ outcome: "success", target: { display: "Team Wiki" }, actor: { display: aliceEmail } });
  });

  it("enforces PKCE, secrets and redirect URIs at the token endpoint", async () => {
    const rp = await relyingParty(app.app.oidc.client_id, app.client_secret);
    const verifier = oidc.randomPKCECodeVerifier();
    const url = oidc.buildAuthorizationUrl(rp, { redirect_uri: REDIRECT, scope: "openid", state: "x", code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: "S256" });
    const code = new URL((await authorize(url, alice)).location!).searchParams.get("code")!;
    const token = (form: Record<string, string>, auth = `${app.app.oidc.client_id}:${app.client_secret}`) =>
      h.app.request(`/oidc/${slug}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(auth).toString("base64")}` },
        body: new URLSearchParams(form),
      });
    const bad = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier" });
    expect(bad.status).toBe(400);
    expect(((await bad.json()) as { error: string }).error).toBe("invalid_grant");
    // The failed attempt consumed the code: it's burned even with the right verifier.
    expect((await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier })).status).toBe(400);
    const badSecret = await token({ grant_type: "authorization_code", code: "whatever", redirect_uri: REDIRECT }, `${app.app.oidc.client_id}:nxcs_wrong`);
    expect(badSecret.status).toBe(401);
    expect(((await badSecret.json()) as { error: string }).error).toBe("invalid_client");
  });

  it("never redirects to unregistered addresses", async () => {
    const d = await authorize(new URL(`${WEB}/x?client_id=${app.app.oidc.client_id}&redirect_uri=${encodeURIComponent("https://evil.example.com/cb")}&response_type=code&scope=openid`), alice);
    expect(d).toMatchObject({ action: "error", code: "invalid_redirect_uri" });
  });

  it("sends people without a session to login, or returns login_required for prompt=none", async () => {
    const q = `client_id=${app.app.oidc.client_id}&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&scope=openid&state=abc`;
    expect((await authorize(new URL(`${WEB}/x?${q}`))).action).toBe("login");
    const none = await authorize(new URL(`${WEB}/x?${q}&prompt=none`));
    expect(new URL(none.location!).searchParams.get("error")).toBe("login_required");
    expect(new URL(none.location!).searchParams.get("state")).toBe("abc");
  });

  it("supports public clients (SPAs) with PKCE only", async () => {
    const spa = await createApp({ name: "Dashboard SPA", client_type: "public", redirect_uris: ["http://localhost:5173/callback"] });
    expect(spa.client_secret).toBeNull();
    await h.call("POST", `/v1/apps/${spa.app.id}/assignments`, { token: admin, body: { principals: [{ type: "user", id: aliceId }] } });
    const rp = await relyingParty(spa.app.oidc.client_id, null);
    const noPkce = await authorize(oidc.buildAuthorizationUrl(rp, { redirect_uri: "http://localhost:5173/callback", scope: "openid", state: "s" }), alice);
    expect(new URL(noPkce.location!).searchParams.get("error")).toBe("invalid_request");
    const verifier = oidc.randomPKCECodeVerifier();
    const url = oidc.buildAuthorizationUrl(rp, { redirect_uri: "http://localhost:5173/callback", scope: "openid", state: "s", code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: "S256" });
    const tokens = await oidc.authorizationCodeGrant(rp, new URL((await authorize(url, alice)).location!), { pkceCodeVerifier: verifier, expectedState: "s" });
    expect(tokens.claims()!.sub).toBe(aliceId);
  });

  it("stops issuing tokens once the user is contained", async () => {
    const rp = await relyingParty(app.app.oidc.client_id, app.client_secret);
    const verifier = oidc.randomPKCECodeVerifier();
    const url = oidc.buildAuthorizationUrl(rp, { redirect_uri: REDIRECT, scope: "openid", state: "c", code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: "S256" });
    const callback = new URL((await authorize(url, alice)).location!);
    await h.call("POST", `/v1/users/${aliceId}/contain`, { token: admin, body: { reason: "test" } });
    await expect(oidc.authorizationCodeGrant(rp, callback, { pkceCodeVerifier: verifier, expectedState: "c" })).rejects.toMatchObject({ error: "invalid_grant" });
  });

  it("lists launchable apps for the signed-in user", async () => {
    const other = uniqueEmail("bob");
    await h.call("POST", "/v1/users", { token: admin, body: { email: other, given_name: "Bob", password: PASSWORD } });
    const bob = (await h.call("POST", "/v1/auth/login", { body: { email: other, password: PASSWORD } })).body.token;
    expect((await h.call("GET", "/v1/me/apps", { token: bob })).body.data).toEqual([]);
    const mine = await h.call("GET", "/v1/me/apps", { token: admin });
    expect(mine.status).toBe(200);
  });
});

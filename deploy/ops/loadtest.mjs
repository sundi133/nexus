// Load test for the hot paths: agent check-ins, authenticated API reads, SSO authorize decisions.
//   node deploy/ops/loadtest.mjs [--api http://localhost:8080] [--seconds 20] [--concurrency 32]
// Sets itself up through the public API (a fresh org), so it can run against any environment
// you're allowed to load. Reports throughput and latency percentiles per scenario.
import { createHash, createHmac, randomUUID, webcrypto } from "node:crypto";

const arg = (name, dflt) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : dflt;
};
const API = arg("api", "http://localhost:8080");
const SECONDS = Number(arg("seconds", 20));
const CONCURRENCY = Number(arg("concurrency", 32));
const DEVICES = Number(arg("devices", 64));
const { subtle } = webcrypto;
const b64u = (buf) => Buffer.from(buf).toString("base64url");

async function call(method, path, { token, body, headers = {} } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    redirect: "manual",
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {}
  return { status: res.status, body: json };
}

function totp(secretB32, offset = 0) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secretB32.replace(/=+$/, "")) bits += a.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((x) => parseInt(x, 2)));
  const t = Buffer.alloc(8);
  t.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
  const h = createHmac("sha1", key).update(t).digest();
  const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
}

// A software device agent: P-256 key, ES256 proofs exactly like the Go agent.
async function newDevice() {
  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await subtle.exportKey("jwk", kp.publicKey);
  return { kp, jwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, id: "" };
}
async function proof(dev, path, body, enroll = false) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "nexus-device+jwt", ...(enroll ? { jwk: dev.jwk } : { kid: dev.id }) };
  const claims = { aud: "nexus-agent", htm: "POST", htu: path, bsh: createHash("sha256").update(body).digest("base64url"), jti: randomUUID(), iat: now, exp: now + 120 };
  const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
  const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, dev.kp.privateKey, Buffer.from(input));
  return `${input}.${b64u(sig)}`;
}

async function setup() {
  const email = `load-${randomUUID().slice(0, 8)}@loadtest.example`;
  const s = await call("POST", "/v1/signup", { body: { organization_name: "Load test", email, password: "load-test-passphrase-1234", given_name: "Load" } });
  if (s.status !== 201) throw new Error(`signup failed: ${s.status} ${JSON.stringify(s.body)}`);
  const session = s.body.token;
  const f = await call("POST", "/v1/me/factors/totp", { token: session, body: {} });
  await call("POST", `/v1/me/factors/${f.body.id}/verify`, { token: session, body: { code: totp(f.body.secret) } });
  const key = await call("POST", "/v1/api-keys", { token: session, body: { name: "load test", scopes: ["users:read", "devices:read"], expires_in_days: 1 } });
  if (key.status !== 201) throw new Error(`api key failed: ${key.status} ${JSON.stringify(key.body)}`);
  for (let i = 0; i < 50; i++) await call("POST", "/v1/users", { token: session, body: { email: `u${i}-${randomUUID().slice(0, 6)}@loadtest.example`, given_name: `User${i}` } });
  const app = await call("POST", "/v1/apps", { token: session, body: { protocol: "oidc", name: "Load app", redirect_uris: ["https://load.example.com/cb"] } });
  const me = await call("GET", "/v1/me", { token: session });
  await call("POST", `/v1/apps/${app.body.app.id}/assignments`, { token: session, body: { principals: [{ type: "user", id: me.body.user.id }] } });
  const tok = await call("POST", "/v1/devices/enrollment-tokens", { token: session, body: { name: "load", max_uses: DEVICES } });
  const devices = [];
  for (let i = 0; i < DEVICES; i++) {
    const d = await newDevice();
    const body = JSON.stringify({ token: tok.body.token, device: { hostname: `load-${i}`, platform: "macos", arch: "arm64", agent_version: "0.2.0" } });
    const r = await call("POST", "/v1/agent/enroll", { body, headers: { authorization: `NexusDevice ${await proof(d, "/v1/agent/enroll", body, true)}` } });
    d.id = r.body.device_id;
    devices.push(d);
  }
  return { session, apiKey: key.body.key, slug: me.body.organization.slug, clientId: app.body.app.oidc.client_id, devices };
}

const POSTURE = { disk_encryption: { status: "on" }, firewall: { status: "on" }, screen_lock: { status: "on", delay_seconds: 300 }, system_integrity: { status: "on" } };

async function run(name, op) {
  const lat = [];
  let errors = 0;
  const firstErrors = new Map();
  const end = Date.now() + SECONDS * 1000;
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async (_, w) => {
      for (let i = 0; Date.now() < end; i++) {
        const t = performance.now();
        const status = await op(w, i).catch(() => 0);
        lat.push(performance.now() - t);
        if (status < 200 || status >= 400) {
          errors++;
          firstErrors.set(status, (firstErrors.get(status) ?? 0) + 1);
        }
      }
    }),
  );
  lat.sort((a, b) => a - b);
  const p = (q) => lat[Math.min(lat.length - 1, Math.floor(lat.length * q))].toFixed(1);
  console.log(`${name.padEnd(28)} ${String(Math.round(lat.length / SECONDS)).padStart(6)} req/s   p50 ${p(0.5).padStart(6)} ms   p95 ${p(0.95).padStart(6)} ms   p99 ${p(0.99).padStart(6)} ms   errors ${errors}${errors ? ` ${JSON.stringify(Object.fromEntries(firstErrors))}` : ""}`);
}

console.log(`Setting up against ${API} (${DEVICES} devices)…`);
const ctx = await setup();
console.log(`Running each scenario for ${SECONDS}s at concurrency ${CONCURRENCY}\n`);
await run("agent check-in (signed)", async (w, i) => {
  const d = ctx.devices[(w * 7919 + i) % ctx.devices.length];
  const body = JSON.stringify({ device: { agent_version: "0.2.0" }, posture: POSTURE });
  return (await fetch(API + "/v1/agent/checkin", { method: "POST", headers: { "content-type": "application/json", authorization: `NexusDevice ${await proof(d, "/v1/agent/checkin", body)}` }, body })).status;
});
await run("GET /v1/users (session)", async () => (await fetch(`${API}/v1/users?limit=50`, { headers: { authorization: `Bearer ${ctx.session}` } })).status);
await run("OIDC authorize decision", async () => {
  const q = new URLSearchParams({ client_id: ctx.clientId, redirect_uri: "https://load.example.com/cb", response_type: "code", scope: "openid email", state: "s", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256" });
  return (await fetch(`${API}/v1/sso/oidc/${ctx.slug}/authorize?${q}`, { headers: { authorization: `Bearer ${ctx.session}` } })).status;
});

// API keys are rate limited per key (600/min): a runaway script is throttled, not the tenant.
let ok = 0;
let limited = 0;
for (let i = 0; i < 700; i++) {
  const s = (await fetch(`${API}/v1/users?limit=1`, { headers: { authorization: `Bearer ${ctx.apiKey}` } })).status;
  s === 429 ? limited++ : ok++;
}
console.log(`${"API key rate limit".padEnd(28)} ${ok} allowed, ${limited} throttled (limit 600/min per key) ${ok <= 600 && limited >= 100 ? "✓" : "✗"}`);

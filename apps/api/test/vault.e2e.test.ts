import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bootApp, PASSWORD, uniqueEmail } from "./harness.js";

/** The password manager: zero-knowledge, driven with the same crypto code the browser runs. */

// The browser's own crypto module, loaded at runtime (it lives in the web app, outside this tsconfig).
const CRYPTO = new URL("../../web/src/lib/vault-crypto.ts", import.meta.url).href;
let vc: any;

let h: Awaited<ReturnType<typeof bootApp>>;
let db: pg.Client;
let admin = "";
const people: Record<string, { id: string; token: string; email: string; key?: CryptoKey; publicKey?: string }> = {};
const SECRET = "hunter2-correct-horse-battery";
const iterations = 100_000; // the minimum the server accepts; the browser uses 600,000

async function setUp(who: string, master: string) {
  const acct = await vc.createAccount(master, iterations);
  const r = await h.call("PUT", "/v1/vault/account", { token: people[who]!.token, body: { public_key: acct.publicKey, private_key_enc: acct.privateKeyEnc, kdf: acct.kdf } });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  // Unlock the way the browser does after a reload: fetch, then open with the master password.
  const stored = (await h.call("GET", "/v1/vault/account", { token: people[who]!.token })).body;
  people[who]!.key = await vc.unlock(master, stored.kdf, stored.private_key_enc);
  people[who]!.publicKey = acct.publicKey;
}

beforeAll(async () => {
  vc = await import(/* @vite-ignore */ CRYPTO);
  h = await bootApp();
  db = new pg.Client({ connectionString: process.env.NEXUS_DATABASE_OWNER_URL });
  await db.connect();
  admin = (await h.call("POST", "/v1/signup", { body: { organization_name: "Vault Co", email: uniqueEmail("root"), password: PASSWORD, given_name: "Root" } })).body.token;
  await h.call("PATCH", "/v1/org/settings", { token: admin, body: { mfa_policy: "off" } });
  for (const n of ["alice", "bob", "eve"]) {
    const email = uniqueEmail(n);
    const id = (await h.call("POST", "/v1/users", { token: admin, body: { email, given_name: n, password: PASSWORD } })).body.id;
    people[n] = { id, email, token: (await h.call("POST", "/v1/auth/login", { body: { email, password: PASSWORD } })).body.token };
  }
});
afterAll(async () => {
  await db.end();
  await h.close();
});

describe("password manager", () => {
  let personal = "";
  let team = "";
  let teamKey: CryptoKey;

  it("sets up with a master password; a wrong one doesn't unlock", async () => {
    await setUp("alice", "alice master pw 1");
    await setUp("bob", "bob master pw 1");
    const stored = (await h.call("GET", "/v1/vault/account", { token: people.alice!.token })).body;
    await expect(vc.unlock("wrong", stored.kdf, stored.private_key_enc)).rejects.toThrow("Wrong master password");
    // The public key can't be swapped later (shared vaults are wrapped to it).
    const other = await vc.createAccount("x", iterations);
    expect((await h.call("PUT", "/v1/vault/account", { token: people.alice!.token, body: { public_key: other.publicKey, private_key_enc: other.privateKeyEnc, kdf: other.kdf } })).body.code).toBe("key_change");
  });

  it("stores only ciphertext: items, names and keys", async () => {
    const key = await vc.newVaultKey();
    personal = (await h.call("POST", "/v1/vault/vaults", { token: people.alice!.token, body: { kind: "personal", name_enc: await vc.encryptJson(key, "Personal"), wrapped_key: await vc.wrapFor(key, people.alice!.publicKey!) } })).body.id;
    await h.call("POST", `/v1/vault/vaults/${personal}/items`, { token: people.alice!.token, body: { data: await vc.encryptJson(key, { title: "Bank", url: "https://bank.example", username: "alice", password: SECRET }) } });
    const dump = JSON.stringify((await db.query("SELECT v.name_enc, m.wrapped_key, i.data, a.private_key_enc FROM vaults v JOIN vault_members m ON m.vault_id = v.id LEFT JOIN vault_items i ON i.vault_id = v.id JOIN vault_accounts a ON a.user_id = m.user_id")).rows);
    for (const plain of [SECRET, "bank.example", "Personal", "alice master pw 1"]) expect(dump).not.toContain(plain);

    // Reading it back: unwrap the vault key with the private key, then decrypt.
    const v = (await h.call("GET", "/v1/vault/vaults", { token: people.alice!.token })).body.data[0];
    const k = await vc.unwrap(v.wrapped_key, people.alice!.key!);
    expect(await vc.decryptJson(k, v.name_enc)).toBe("Personal");
    const items = (await h.call("GET", `/v1/vault/vaults/${personal}/items`, { token: people.alice!.token })).body.data;
    expect(await vc.decryptJson(k, items[0].data)).toMatchObject({ password: SECRET });
    // Personal vaults don't get shared, and other people can't see them.
    expect((await h.call("GET", `/v1/vault/vaults/${personal}/items`, { token: people.bob!.token })).status).toBe(404);
    expect((await h.call("PUT", `/v1/vault/vaults/${personal}/members/${people.bob!.id}`, { token: people.alice!.token, body: { role: "viewer", wrapped_key: "AAAA" } })).body.code).toBe("personal_vault");
  });

  it("shares a vault: the key is wrapped to the member's public key; viewers can't write", async () => {
    teamKey = await vc.newVaultKey();
    team = (await h.call("POST", "/v1/vault/vaults", { token: people.alice!.token, body: { kind: "shared", name_enc: await vc.encryptJson(teamKey, "Ops"), wrapped_key: await vc.wrapFor(teamKey, people.alice!.publicKey!) } })).body.id;
    await h.call("POST", `/v1/vault/vaults/${team}/items`, { token: people.alice!.token, body: { data: await vc.encryptJson(teamKey, { title: "AWS root", password: SECRET }) } });
    const bobPub = (await h.call("GET", "/v1/vault/people", { token: people.alice!.token })).body.data.find((x: any) => x.email === people.bob!.email).public_key;
    expect(await vc.fingerprint(bobPub)).toBe(await vc.fingerprint(people.bob!.publicKey!));
    expect((await h.call("PUT", `/v1/vault/vaults/${team}/members/${people.eve!.id}`, { token: people.alice!.token, body: { role: "viewer", wrapped_key: "AAAA" } })).body.code).toBe("not_set_up");
    expect((await h.call("PUT", `/v1/vault/vaults/${team}/members/${people.bob!.id}`, { token: people.alice!.token, body: { role: "viewer", wrapped_key: await vc.wrapFor(teamKey, bobPub) } })).status).toBe(204);

    const v = (await h.call("GET", "/v1/vault/vaults", { token: people.bob!.token })).body.data.find((x: any) => x.id === team);
    const k = await vc.unwrap(v.wrapped_key, people.bob!.key!);
    const items = (await h.call("GET", `/v1/vault/vaults/${team}/items`, { token: people.bob!.token })).body.data;
    expect(await vc.decryptJson(k, items[0].data)).toMatchObject({ title: "AWS root", password: SECRET });
    expect((await h.call("POST", `/v1/vault/vaults/${team}/items`, { token: people.bob!.token, body: { data: await vc.encryptJson(k, { title: "x" }) } })).status).toBe(403);
    expect((await h.call("PUT", `/v1/vault/vaults/${team}/members/${people.eve!.id}`, { token: people.bob!.token, body: { role: "viewer", wrapped_key: "AAAA" } })).status).toBe(403);
    // Using a secret is audited, without the secret.
    await h.call("POST", `/v1/vault/items/${items[0].id}/used`, { token: people.bob!.token, body: { action: "copied_password" } });
    const ev = (await db.query("SELECT details FROM audit_events WHERE type = 'vault.item_used' AND details->>'item_id' = $1", [items[0].id])).rows[0].details;
    expect(ev).toEqual({ item_id: items[0].id, action: "copied_password" });
  });

  it("a new master password re-encrypts only the private key; offboarding removes every vault", async () => {
    const stored = (await h.call("GET", "/v1/vault/account", { token: people.bob!.token })).body;
    const next = await vc.rewrapPrivateKey("bob master pw 1", "bob master pw 2", stored.kdf, stored.private_key_enc, iterations);
    expect((await h.call("PUT", "/v1/vault/account", { token: people.bob!.token, body: { public_key: stored.public_key, ...{ private_key_enc: next.privateKeyEnc, kdf: next.kdf } } })).status).toBe(200);
    const again = (await h.call("GET", "/v1/vault/account", { token: people.bob!.token })).body;
    const key = await vc.unlock("bob master pw 2", again.kdf, again.private_key_enc);
    const v = (await h.call("GET", "/v1/vault/vaults", { token: people.bob!.token })).body.data.find((x: any) => x.id === team);
    expect(await vc.decryptJson(await vc.unwrap(v.wrapped_key, key), v.name_enc)).toBe("Ops"); // shared vaults still open

    await h.call("POST", `/v1/users/${people.alice!.id}/offboard`, { token: admin, body: { reason: "Left" } });
    expect((await db.query("SELECT count(*)::int AS n FROM vaults WHERE id = $1", [personal])).rows[0].n).toBe(0); // nobody left in it
    expect((await db.query("SELECT user_id FROM vault_members WHERE vault_id = $1", [team])).rows.map((r: { user_id: string }) => r.user_id)).toEqual([people.bob!.id]);
    // Alice was Ops's only owner: Bob, the one left, becomes its owner so it isn't stuck.
    expect((await db.query("SELECT role FROM vault_members WHERE vault_id = $1", [team])).rows[0].role).toBe("owner");
    const gen = vc.generatePassword(24);
    expect(gen).toHaveLength(24);
    expect(gen).not.toMatch(/[0O1lI]/);
  });
});

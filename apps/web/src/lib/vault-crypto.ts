/**
 * Password manager crypto, done entirely on the person's device (WebCrypto). The server only ever
 * sees ciphertext and public keys.
 *
 * - The master password → PBKDF2-SHA256 (600,000 rounds, random salt) → an AES-256-GCM key that
 *   encrypts the person's RSA-OAEP private key.
 * - Each vault has a random AES-256-GCM key; items and the vault's name are encrypted with it.
 * - A vault key is wrapped (RSA-OAEP-256) to every member's public key: sharing never reveals it
 *   to the server.
 */

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();
export const KDF_ITERATIONS = 600_000;

export type Sealed = { iv: string; ct: string };
export type Kdf = { alg: "PBKDF2-SHA256"; iterations: number; salt: string };

const b64 = (b: ArrayBuffer | Uint8Array) => {
  const bytes = b instanceof Uint8Array ? b : new Uint8Array(b);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
};
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const rand = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export async function masterKey(password: string, kdf: Kdf): Promise<CryptoKey> {
  const base = await subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: unb64(kdf.salt), iterations: kdf.iterations }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function seal(key: CryptoKey, data: Uint8Array<ArrayBuffer>): Promise<Sealed> {
  const iv = rand(12);
  return { iv: b64(iv), ct: b64(await subtle.encrypt({ name: "AES-GCM", iv }, key, data)) };
}
async function open(key: CryptoKey, s: Sealed): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(s.iv) }, key, unb64(s.ct)));
}

const RSA = { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" } as const;

/** First use: a key pair, the private half encrypted with the master password. */
export async function createAccount(password: string, iterations = KDF_ITERATIONS) {
  const kdf: Kdf = { alg: "PBKDF2-SHA256", iterations, salt: b64(rand(16)) };
  const pair = (await subtle.generateKey(RSA, true, ["wrapKey", "unwrapKey"])) as CryptoKeyPair;
  const mk = await masterKey(password, kdf);
  const privateKeyEnc = await seal(mk, new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey)));
  return { kdf, publicKey: b64(await subtle.exportKey("spki", pair.publicKey)), privateKeyEnc, privateKey: pair.privateKey };
}

/** Unlock: the master password opens the private key (a wrong one fails here). */
export async function unlock(password: string, kdf: Kdf, privateKeyEnc: Sealed): Promise<CryptoKey> {
  const pkcs8 = await open(await masterKey(password, kdf), privateKeyEnc).catch(() => {
    throw new Error("Wrong master password");
  });
  return subtle.importKey("pkcs8", pkcs8, RSA, false, ["unwrapKey"]);
}

/** Changing the master password re-encrypts only the private key. */
export async function rewrapPrivateKey(oldPassword: string, newPassword: string, kdf: Kdf, privateKeyEnc: Sealed, iterations = KDF_ITERATIONS) {
  const pkcs8 = await open(await masterKey(oldPassword, kdf), privateKeyEnc).catch(() => {
    throw new Error("Wrong master password");
  });
  const next: Kdf = { alg: "PBKDF2-SHA256", iterations, salt: b64(rand(16)) };
  return { kdf: next, privateKeyEnc: await seal(await masterKey(newPassword, next), pkcs8) };
}

export const newVaultKey = () => subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]) as Promise<CryptoKey>;

export async function wrapFor(vaultKey: CryptoKey, publicKeyB64: string): Promise<string> {
  const pub = await subtle.importKey("spki", unb64(publicKeyB64), RSA, false, ["wrapKey"]);
  return b64(await subtle.wrapKey("raw", vaultKey, pub, { name: "RSA-OAEP" }));
}

export async function unwrap(wrapped: string, privateKey: CryptoKey): Promise<CryptoKey> {
  return subtle.unwrapKey("raw", unb64(wrapped), privateKey, { name: "RSA-OAEP" }, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

export type Item = { title: string; url?: string; username?: string; password?: string; notes?: string; totp?: string };

export const encryptJson = async (key: CryptoKey, v: unknown) => seal(key, te.encode(JSON.stringify(v)));
export const decryptJson = async <T>(key: CryptoKey, s: Sealed) => JSON.parse(td.decode(await open(key, s))) as T;

/** A short fingerprint of a public key, to compare out of band before sharing. */
export async function fingerprint(publicKeyB64: string) {
  const h = new Uint8Array(await subtle.digest("SHA-256", unb64(publicKeyB64)));
  return Array.from(h.slice(0, 8), (x) => x.toString(16).padStart(2, "0")).join(":");
}

/** A random password: letters, digits and symbols, no look-alikes. */
export function generatePassword(length = 20, symbols = true) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789" + (symbols ? "!#$%&*+-=?@^_" : "");
  const out: string[] = [];
  const limit = 256 - (256 % alphabet.length); // no modulo bias
  while (out.length < length) {
    for (const b of rand(length * 2)) if (b < limit && out.length < length) out.push(alphabet[b % alphabet.length]!);
  }
  return out.join("");
}

import { exportJWK, exportPKCS8, generateKeyPair, importPKCS8, SignJWT, type JWK, type JWTPayload } from "jose";
import { randomBytes } from "node:crypto";
import type { Deps } from "../context.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";

/**
 * Per-tenant RS256 signing keys (ARCHITECTURE §7.1). Created lazily on first
 * use; the private key is sealed at rest. Rotation adds a new active key and
 * retires the old one, which stays in the JWKS so issued tokens keep verifying.
 */

type KeyRow = { kid: string; private_key_sealed: Buffer };
const RETIRED_PUBLISH_MS = 7 * 24 * 3600_000;
const cache = new Map<string, { kid: string; key: CryptoKey }>(); // kid → imported private key

export async function createKey(tx: Tx, deps: Deps, orgId: string) {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
  const kid = randomBytes(12).toString("base64url");
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" };
  const sealed = deps.sealer.seal(Buffer.from(await exportPKCS8(privateKey)), kid);
  await tx
    .insertInto("signing_keys")
    .values({ id: newId(), org_id: orgId, kid, public_jwk: JSON.stringify(jwk), private_key_sealed: sealed })
    .execute();
  return { kid, private_key_sealed: sealed } satisfies KeyRow;
}

async function activeKey(tx: Tx, deps: Deps, orgId: string) {
  const row: KeyRow =
    (await tx
      .selectFrom("signing_keys")
      .select(["kid", "private_key_sealed"])
      .where("purpose", "=", "oidc")
      .where("status", "=", "active")
      .orderBy("created_at", "desc")
      .executeTakeFirst()) ?? (await createKey(tx, deps, orgId));
  const hit = cache.get(row.kid);
  if (hit) return hit;
  const pem = deps.sealer.open(row.private_key_sealed, row.kid).toString("utf8");
  const entry = { kid: row.kid, key: await importPKCS8(pem, "RS256") };
  cache.set(row.kid, entry);
  return entry;
}

export async function signJwt(tx: Tx, deps: Deps, orgId: string, payload: JWTPayload, opts: { typ?: string; expiresInSec: number }) {
  const { kid, key } = await activeKey(tx, deps, orgId);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid, typ: opts.typ ?? "JWT" })
    .setIssuedAt()
    .setExpirationTime(`${opts.expiresInSec}s`)
    .sign(key);
}

/** Public keys for the tenant's JWKS (active and retired). Creates the first key if none exists yet. */
export async function publicJwks(tx: Tx, deps: Deps, orgId: string): Promise<{ keys: JWK[] }> {
  // Retired keys stay published for a week so tokens they signed keep verifying through caches.
  const oidcKeys = () =>
    tx
      .selectFrom("signing_keys")
      .select("public_jwk")
      .where("purpose", "=", "oidc")
      .where((eb) => eb.or([eb("status", "=", "active"), eb("retired_at", ">", new Date(Date.now() - RETIRED_PUBLISH_MS))]))
      .orderBy("created_at", "desc")
      .execute();
  let rows = await oidcKeys();
  if (!rows.length) {
    await activeKey(tx, deps, orgId);
    rows = await oidcKeys();
  }
  return { keys: rows.map((r) => r.public_jwk as JWK) };
}

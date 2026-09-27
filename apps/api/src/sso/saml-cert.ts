import "reflect-metadata"; // @peculiar/x509 needs it; don't rely on another package having loaded it first
import * as x509 from "@peculiar/x509";
import { createHash, randomBytes, webcrypto } from "node:crypto";
import type { Deps } from "../context.js";
import type { Tx } from "../platform/db.js";
import { newId } from "../platform/ids.js";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;
const VALIDITY_YEARS = 10; // SAML IdP certs are long-lived; rotation is explicit and announced to SPs

export type SamlCert = { kid: string; certPem: string; privateKeyPem: string; notAfter: Date; fingerprintSha256: string };

const toPem = (label: string, der: ArrayBuffer) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;

export const certBody = (pem: string) => pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");

export function fingerprint(certPem: string) {
  const hex = createHash("sha256").update(Buffer.from(certBody(certPem), "base64")).digest("hex").toUpperCase();
  return hex.match(/.{2}/g)!.join(":");
}

export async function createSamlCert(tx: Tx, deps: Deps, orgId: string, status: "active" | "next" = "active"): Promise<SamlCert> {
  const { name: orgName } = await tx.selectFrom("organizations").select("name").where("id", "=", orgId).executeTakeFirstOrThrow();
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(notBefore);
  notAfter.setFullYear(notAfter.getFullYear() + VALIDITY_YEARS);
  const cn = `Votal Nexus SAML - ${orgName}`.replace(/[,+="\\<>;#]/g, " ");
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: randomBytes(16).toString("hex").replace(/^[89a-f]/, "1"),
    name: `CN=${cn}, O=Votal Nexus`,
    notBefore,
    notAfter,
    signingAlgorithm: ALG,
    keys,
    extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true)],
  });
  const certPem = cert.toString("pem") + "\n";
  const privateKeyPem = toPem("PRIVATE KEY", await webcrypto.subtle.exportKey("pkcs8", keys.privateKey));
  const kid = `saml-${randomBytes(9).toString("base64url")}`;
  await tx
    .insertInto("signing_keys")
    .values({
      id: newId(),
      org_id: orgId,
      kid,
      alg: "RS256",
      purpose: "saml",
      status,
      public_jwk: JSON.stringify({}),
      private_key_sealed: deps.sealer.seal(Buffer.from(privateKeyPem), kid),
      cert_pem: certPem,
      not_after: notAfter,
    })
    .execute();
  return { kid, certPem, privateKeyPem, notAfter, fingerprintSha256: fingerprint(certPem) };
}

/** The tenant's active SAML signing certificate, created on first use. */
export async function activeSamlCert(tx: Tx, deps: Deps, orgId: string): Promise<SamlCert> {
  const row = await tx
    .selectFrom("signing_keys")
    .select(["kid", "cert_pem", "private_key_sealed", "not_after"])
    .where("purpose", "=", "saml")
    .where("status", "=", "active")
    .orderBy("created_at", "desc")
    .executeTakeFirst();
  if (!row?.cert_pem) return createSamlCert(tx, deps, orgId);
  return {
    kid: row.kid,
    certPem: row.cert_pem,
    privateKeyPem: deps.sealer.open(row.private_key_sealed, row.kid).toString("utf8"),
    notAfter: row.not_after!,
    fingerprintSha256: fingerprint(row.cert_pem),
  };
}

/** Certificates SPs should trust right now: the active one, plus the next one during a rotation. */
export async function publishedSamlCerts(tx: Tx, deps: Deps, orgId: string) {
  const active = await activeSamlCert(tx, deps, orgId);
  const next = await tx
    .selectFrom("signing_keys")
    .select("cert_pem")
    .where("purpose", "=", "saml")
    .where("status", "=", "next")
    .executeTakeFirst();
  return [active.certPem, ...(next?.cert_pem ? [next.cert_pem] : [])];
}

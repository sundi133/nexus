import "reflect-metadata";
import { ContentInfo, SignedData } from "@peculiar/asn1-cms";
import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1js from "asn1js";
import * as x509 from "@peculiar/x509";
import forge from "node-forge";
import { createHash, createPublicKey, randomBytes, verify as cryptoVerify, webcrypto, X509Certificate } from "node:crypto";
import type { Deps } from "../context.js";
import type { Tx } from "../platform/db.js";

/**
 * The organization's Apple MDM PKI: a private CA that issues each enrolling Mac its identity, and
 * checks of the CMS signature Macs put on every MDM message (Mdm-Signature). The CA is never
 * installed on devices as a trusted root: it only vouches for MDM identities to Nexus.
 */

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;
const pem = (label: string, der: ArrayBuffer | Buffer) => `-----BEGIN ${label}-----\n${Buffer.from(der as ArrayBuffer).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;
const serial = () => randomBytes(16).toString("hex").replace(/^[89a-f]/, "1");
export const caAad = (orgId: string) => `apple_mdm_ca:${orgId}`;
export const pushKeyAad = (orgId: string) => `apple_mdm_push:${orgId}`;

export const certFingerprint = (der: Buffer) => createHash("sha256").update(der).digest("hex");

/** The org's CA, created on first use. */
export async function ensureCa(tx: Tx, deps: Deps, orgId: string) {
  const cur = await tx.selectFrom("apple_mdm_settings").select(["ca_cert", "ca_key"]).where("org_id", "=", orgId).executeTakeFirst();
  if (cur) return { certPem: cur.ca_cert, keyPem: deps.sealer.open(cur.ca_key, caAad(orgId)).toString() };
  const { name } = await tx.selectFrom("organizations").select("name").where("id", "=", orgId).executeTakeFirstOrThrow();
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(notBefore);
  notAfter.setFullYear(notAfter.getFullYear() + 20);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(),
    name: `CN=${`Votal Nexus MDM CA - ${name}`.replace(/[,+="\\<>;#]/g, " ")}, O=Votal Nexus`,
    notBefore,
    notAfter,
    signingAlgorithm: ALG,
    keys,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true), new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)],
  });
  const certPem = cert.toString("pem") + "\n";
  const keyPem = pem("PRIVATE KEY", await webcrypto.subtle.exportKey("pkcs8", keys.privateKey));
  await tx.insertInto("apple_mdm_settings").values({ org_id: orgId, ca_cert: certPem, ca_key: deps.sealer.seal(Buffer.from(keyPem), caAad(orgId)) }).execute();
  return { certPem, keyPem };
}

/** A device identity signed by the CA: what the enrollment profile carries (as PKCS#12). */
export async function issueIdentity(ca: { certPem: string; keyPem: string }, commonName: string) {
  const caCert = new x509.X509Certificate(ca.certPem);
  const caKey = await webcrypto.subtle.importKey("pkcs8", Buffer.from(ca.keyPem.replace(/-----[^-]+-----|\s/g, ""), "base64"), ALG, false, ["sign"]);
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(notBefore);
  notAfter.setFullYear(notAfter.getFullYear() + 5);
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(),
    subject: `CN=${commonName.replace(/[,+="\\<>;#]/g, " ")}`,
    issuer: caCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: ALG,
    publicKey: keys.publicKey,
    signingKey: caKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.clientAuth]),
    ],
  });
  const der = Buffer.from(cert.rawData);
  return { certPem: cert.toString("pem") + "\n", keyPem: pem("PRIVATE KEY", await webcrypto.subtle.exportKey("pkcs8", keys.privateKey)), fingerprint: certFingerprint(der) };
}

/** PKCS#12 with the identity (and its CA), protected by a one-time password carried in the same profile. */
export function pkcs12(identity: { certPem: string; keyPem: string }, caPem: string, password: string): Buffer {
  const key = forge.pki.privateKeyFromPem(identity.keyPem);
  const p12 = forge.pkcs12.toPkcs12Asn1(key, [forge.pki.certificateFromPem(identity.certPem), forge.pki.certificateFromPem(caPem)], password, { algorithm: "3des", friendlyName: "Votal Nexus MDM identity" });
  return Buffer.from(forge.asn1.toDer(p12).getBytes(), "binary");
}

/** The first signer's signed attributes, byte for byte: ContentInfo → [0] → SignedData → signerInfos → SignerInfo → [0]. */
function rawSignedAttrs(cms: Buffer): Buffer {
  const seq = (n: asn1js.AsnType | undefined) => ((n as asn1js.Sequence | undefined)?.valueBlock?.value ?? []) as asn1js.AsnType[];
  const top = asn1js.fromBER(new Uint8Array(cms).buffer);
  const signedData = seq(seq(top.result)[1])[0];
  const signerInfos = seq(signedData).at(-1);
  const attrs = seq(seq(signerInfos)[0]).find((n) => n.idBlock.tagClass === 3 && n.idBlock.tagNumber === 0);
  if (!attrs) throw new SignatureError("malformed Mdm-Signature");
  return Buffer.from(attrs.toBER(false));
}

const DIGEST: Record<string, string> = {
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
};
const MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

export class SignatureError extends Error {}

/**
 * Checks an Mdm-Signature header (base64 detached CMS SignedData) over the request body and
 * returns the signer's certificate fingerprint. The caller decides whether it trusts that
 * certificate (Nexus trusts only identities it issued).
 */
export function verifyMdmSignature(body: Buffer, header: string | undefined): { fingerprint: string; cert: X509Certificate } {
  if (!header) throw new SignatureError("missing Mdm-Signature");
  const cms = Buffer.from(header, "base64");
  return checkSigned(parseSigned(cms), cms, body);
}

/** Opens CMS SignedData that carries its content (a Mac's machine info in Setup Assistant) and checks it. */
export function openSignedContent(cms: Buffer): { content: Buffer; fingerprint: string; cert: X509Certificate } {
  const signed = parseSigned(cms);
  const e = signed.encapContentInfo.eContent;
  const content = e?.single ? Buffer.from(e.single.buffer) : e?.any ? Buffer.from(e.any) : null;
  if (!content) throw new SignatureError("the signed data has no content");
  return { content, ...checkSigned(signed, cms, content) };
}

function parseSigned(cms: Buffer): SignedData {
  try {
    const ci = AsnConvert.parse(cms, ContentInfo);
    return AsnConvert.parse(ci.content, SignedData);
  } catch {
    throw new SignatureError("malformed signature");
  }
}

function checkSigned(signed: SignedData, cms: Buffer, body: Buffer): { fingerprint: string; cert: X509Certificate } {
  const si = signed.signerInfos[0];
  const certChoice = signed.certificates?.find((c) => c.certificate)?.certificate;
  if (!si || !certChoice || signed.signerInfos.length !== 1) throw new SignatureError("the signature needs exactly one signer with its certificate");
  const certDer = Buffer.from(AsnConvert.serialize(certChoice));
  const cert = new X509Certificate(certDer);
  const hash = DIGEST[si.digestAlgorithm.algorithm];
  if (!hash) throw new SignatureError("unsupported digest");
  const contentDigest = createHash(hash).update(body).digest();
  let signedData: Buffer;
  if (si.signedAttrs?.length) {
    const md = si.signedAttrs.find((a) => a.attrType === MESSAGE_DIGEST)?.attrValues[0];
    // The attribute's value is an OCTET STRING: its DER ends with the digest.
    const mdBytes = md ? Buffer.from(md).subarray(-contentDigest.length) : null;
    if (!mdBytes || !mdBytes.equals(contentDigest)) throw new SignatureError("the signature doesn't cover this body");
    // Signed attributes are signed as a DER SET OF (tag 0x31), not the [0] they're stored as.
    // Use the bytes exactly as sent: re-encoding could reorder them.
    const der = rawSignedAttrs(cms);
    signedData = Buffer.concat([Buffer.from([0x31]), der.subarray(1)]);
  } else {
    signedData = body;
  }
  const ok = cryptoVerify(hash, signedData, createPublicKey(cert.publicKey.export({ type: "spki", format: "pem" })), Buffer.from(si.signature.buffer));
  if (!ok) throw new SignatureError("bad signature");
  return { fingerprint: certFingerprint(certDer), cert };
}

// ---- The push certificate (APNs for MDM) ----------------------------------------------------

/** A CSR for the organization's MDM push certificate: signed by an MDM vendor, then uploaded to Apple. */
export async function pushCsr(orgName: string) {
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({ name: `CN=${`Votal Nexus MDM - ${orgName}`.replace(/[,+="\\<>;#]/g, " ")}, O=Votal Nexus`, keys, signingAlgorithm: ALG });
  return { csrPem: csr.toString("pem") + "\n", keyPem: pem("PRIVATE KEY", await webcrypto.subtle.exportKey("pkcs8", keys.privateKey)) };
}

const UID = "0.9.2342.19200300.100.1.1";

/** Reads Apple's MDM push certificate: its topic (UID), expiry, and that it matches our key. */
export function readPushCert(certPem: string, keyPem: string) {
  let cert: x509.X509Certificate;
  try {
    cert = new x509.X509Certificate(certPem);
  } catch {
    throw new Error("That isn't a PEM certificate");
  }
  const uid = cert.subjectName.getField(UID)[0] ?? "";
  if (!uid.startsWith("com.apple.mgmt.")) throw new Error("That isn't an Apple MDM push certificate (its subject has no com.apple.mgmt topic)");
  const pub = createPublicKey({ key: Buffer.from(cert.publicKey.rawData), format: "der", type: "spki" }).export({ type: "spki", format: "der" }) as Buffer;
  const mine = createPublicKey(keyPem).export({ type: "spki", format: "der" }) as Buffer;
  if (!pub.equals(mine)) throw new Error("This certificate wasn't made from Nexus's current CSR. Download the CSR again and use that one.");
  return { topic: uid, notAfter: cert.notAfter };
}

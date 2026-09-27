import "reflect-metadata";
import forge from "node-forge";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import { describe, expect, it } from "vitest";
import { issueIdentity, pkcs12, pushCsr, readPushCert, SignatureError, verifyMdmSignature } from "./pki.js";

const oids = forge.pki.oids as Record<"sha256" | "sha1" | "contentType" | "data" | "messageDigest" | "signingTime" | "certBag" | "pkcs8ShroudedKeyBag", string>;

/** Signs like a Mac does: detached CMS SignedData with signed attributes, base64. */
export function macSign(body: Buffer, identity: { certPem: string; keyPem: string }, digest = oids.sha256) {
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(body.toString("binary"));
  p7.addCertificate(forge.pki.certificateFromPem(identity.certPem));
  p7.addSigner({
    key: forge.pki.privateKeyFromPem(identity.keyPem) as forge.pki.rsa.PrivateKey,
    certificate: forge.pki.certificateFromPem(identity.certPem),
    digestAlgorithm: digest,
    authenticatedAttributes: [
      { type: oids.contentType, value: oids.data },
      { type: oids.messageDigest },
      { type: oids.signingTime, value: new Date() as unknown as string },
    ],
  });
  p7.sign({ detached: true });
  return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), "binary").toString("base64");
}

async function testCa() {
  const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 } as const;
  const keys = (await webcrypto.subtle.generateKey(ALG, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({ serialNumber: "01", name: "CN=Test CA", notBefore: new Date(Date.now() - 1000), notAfter: new Date(Date.now() + 86_400_000), signingAlgorithm: ALG, keys, extensions: [new x509.BasicConstraintsExtension(true, 0, true)] });
  const pk = Buffer.from(await webcrypto.subtle.exportKey("pkcs8", keys.privateKey)).toString("base64");
  return { certPem: cert.toString("pem"), keyPem: `-----BEGIN PRIVATE KEY-----\n${pk.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`, keys };
}

describe("Apple MDM PKI", () => {
  it("issues an identity a Mac can import, and verifies what it signs", async () => {
    const ca = await testCa();
    const id = await issueIdentity(ca, "Mac of Alice");
    // The profile's PKCS#12 opens with its password and holds the key and certificate.
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pkcs12(id, ca.certPem, "s3cret").toString("binary")), "s3cret");
    expect(p12.getBags({ bagType: oids.certBag })[oids.certBag]!.length).toBe(2);
    expect(p12.getBags({ bagType: oids.pkcs8ShroudedKeyBag })[oids.pkcs8ShroudedKeyBag]!.length).toBe(1);

    const body = Buffer.from('<?xml version="1.0"?><plist version="1.0"><dict><key>MessageType</key><string>Authenticate</string></dict></plist>');
    for (const digest of [oids.sha256, oids.sha1]) {
      expect(verifyMdmSignature(body, macSign(body, id, digest)).fingerprint).toBe(id.fingerprint);
    }
    // A different body, a missing header, or garbage: refused.
    const sig = macSign(body, id);
    expect(() => verifyMdmSignature(Buffer.concat([body, Buffer.from(" ")]), sig)).toThrow(SignatureError);
    expect(() => verifyMdmSignature(body, undefined)).toThrow("missing");
    expect(() => verifyMdmSignature(body, "bm90IGNtcw==")).toThrow(SignatureError);
    // Signed by another key but claiming this certificate: refused.
    const other = await issueIdentity(ca, "Mallory");
    const forged = macSign(body, { certPem: id.certPem, keyPem: other.keyPem });
    expect(() => verifyMdmSignature(body, forged)).toThrow(SignatureError);
  });

  it("reads Apple's push certificate and checks it matches Nexus's CSR", async () => {
    const { csrPem, keyPem } = await pushCsr("Acme");
    const csr = new x509.Pkcs10CertificateRequest(csrPem);
    const apple = await testCa();
    const ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;
    const issued = await x509.X509CertificateGenerator.create({
      serialNumber: "02",
      subject: "0.9.2342.19200300.100.1.1=com.apple.mgmt.External.1234abcd-0000-4000-8000-000000000001, CN=APSP:1234, C=US",
      issuer: "CN=Test CA",
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 365 * 86_400_000),
      signingAlgorithm: ALG,
      publicKey: await csr.publicKey.export(),
      signingKey: apple.keys.privateKey,
    });
    expect(readPushCert(issued.toString("pem"), keyPem)).toMatchObject({ topic: "com.apple.mgmt.External.1234abcd-0000-4000-8000-000000000001" });
    const other = await pushCsr("Acme");
    expect(() => readPushCert(issued.toString("pem"), other.keyPem)).toThrow("current CSR");
    expect(() => readPushCert(apple.certPem, keyPem)).toThrow("com.apple.mgmt");
  });
});

import forge from "node-forge";
import plist from "plist";

const oids = forge.pki.oids as Record<"sha256" | "contentType" | "data" | "messageDigest" | "signingTime" | "certBag" | "pkcs8ShroudedKeyBag", string>;

/** A Mac enrolled from a Nexus profile: it holds the profile's identity and signs MDM messages with it. */
export class FakeMac {
  readonly certPem: string;
  readonly keyPem: string;
  readonly profile: Record<string, any>;
  constructor(
    profileBytes: Buffer,
    readonly udid = `UDID-${Math.random().toString(16).slice(2, 10).toUpperCase()}`,
    readonly serial = `C02${Math.random().toString(36).slice(2, 9).toUpperCase()}`,
  ) {
    this.profile = plist.parse(profileBytes.toString("utf8")) as Record<string, any>;
    const idp = this.payload("com.apple.security.pkcs12");
    const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer((idp.PayloadContent as Buffer).toString("binary")), idp.Password as string);
    const key = p12.getBags({ bagType: oids.pkcs8ShroudedKeyBag })[oids.pkcs8ShroudedKeyBag]![0]!.key!;
    const cert = p12.getBags({ bagType: oids.certBag })[oids.certBag]!.find((b) => b.cert && b.cert.subject.getField("CN")?.value?.startsWith("Nexus MDM"))!.cert!;
    this.keyPem = forge.pki.privateKeyToPem(key);
    this.certPem = forge.pki.certificateToPem(cert);
  }

  payload(type: string) {
    return (this.profile.PayloadContent as Record<string, unknown>[]).find((p) => p.PayloadType === type)!;
  }
  get mdm() {
    return this.payload("com.apple.mdm") as { ServerURL: string; CheckInURL: string; Topic: string; SignMessage: boolean; IdentityCertificateUUID: string };
  }

  /** Detached CMS SignedData over the body, as Macs send in Mdm-Signature. */
  sign(body: string, as: { certPem: string; keyPem: string } = this) {
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(Buffer.from(body).toString("binary"));
    p7.addCertificate(forge.pki.certificateFromPem(as.certPem));
    p7.addSigner({
      key: forge.pki.privateKeyFromPem(as.keyPem) as forge.pki.rsa.PrivateKey,
      certificate: forge.pki.certificateFromPem(as.certPem),
      digestAlgorithm: oids.sha256,
      authenticatedAttributes: [{ type: oids.contentType, value: oids.data }, { type: oids.messageDigest }, { type: oids.signingTime, value: new Date() as unknown as string }],
    });
    p7.sign({ detached: true });
    return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), "binary").toString("base64");
  }
}

export const build = (o: Record<string, unknown>) => plist.build(o as plist.PlistValue);
export const parse = (s: string) => (s ? (plist.parse(s) as Record<string, any>) : null);

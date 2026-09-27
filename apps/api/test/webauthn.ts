import { isoCBOR } from "@simplewebauthn/server/helpers";
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const sha256 = (b: Uint8Array | Buffer | string) => createHash("sha256").update(b).digest();

/**
 * A software passkey (ES256, "none" attestation) that produces real WebAuthn
 * responses, so tests exercise the same verification path as a browser.
 */
export class SoftAuthenticator {
  private readonly key: KeyObject;
  private readonly cose: Uint8Array;
  readonly credentialId = randomBytes(16);
  private counter = 0;

  constructor(
    private readonly origin = "http://localhost:3100",
    private readonly rpId = "localhost",
  ) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.key = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    const map = new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, Buffer.from(jwk.x!, "base64url")],
      [-3, Buffer.from(jwk.y!, "base64url")],
    ]);
    this.cose = isoCBOR.encode(map);
  }

  private clientData(type: string, challenge: string) {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }));
  }

  register(options: { challenge: string }) {
    const clientDataJSON = this.clientData("webauthn.create", options.challenge);
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialId.length);
    const authData = Buffer.concat([
      sha256(this.rpId),
      Buffer.from([0x45]), // UP | UV | AT
      Buffer.alloc(4), // sign count 0
      Buffer.alloc(16), // AAGUID
      idLen,
      this.credentialId,
      Buffer.from(this.cose),
    ]);
    const attestationObject = isoCBOR.encode(
      new Map<string, string | Map<string, string> | Uint8Array>([
        ["fmt", "none"],
        ["attStmt", new Map<string, string>()],
        ["authData", authData],
      ]),
    );
    return {
      id: b64u(this.credentialId),
      rawId: b64u(this.credentialId),
      type: "public-key",
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ["internal"] },
      clientExtensionResults: {},
    };
  }

  authenticate(options: { challenge: string }) {
    const clientDataJSON = this.clientData("webauthn.get", options.challenge);
    const count = Buffer.alloc(4);
    count.writeUInt32BE(++this.counter);
    const authData = Buffer.concat([sha256(this.rpId), Buffer.from([0x05]), count]); // UP | UV
    const signature = sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), this.key);
    return {
      id: b64u(this.credentialId),
      rawId: b64u(this.credentialId),
      type: "public-key",
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature) },
      clientExtensionResults: {},
    };
  }
}

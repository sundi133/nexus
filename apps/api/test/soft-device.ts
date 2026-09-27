import { exportJWK, generateKeyPair, SignJWT, type CryptoKey as JoseKey } from "jose";
import { createHash, randomUUID } from "node:crypto";

/** A software device agent: P-256 key + signed proofs, exactly what the Go agent sends. */
export class SoftDevice {
  id = "";
  private key!: { privateKey: JoseKey; publicKey: JoseKey };
  async init() {
    this.key = await generateKeyPair("ES256", { extractable: true });
    return this;
  }
  async proof(path: string, body: string, opts: { method?: string; iatOffset?: number; jti?: string; enroll?: boolean; bodyForHash?: string } = {}) {
    const iat = Math.floor(Date.now() / 1000) + (opts.iatOffset ?? 0);
    const header = opts.enroll
      ? { alg: "ES256", typ: "nexus-device+jwt", jwk: await exportJWK(this.key.publicKey) }
      : { alg: "ES256", typ: "nexus-device+jwt", kid: this.id };
    return new SignJWT({
      htm: opts.method ?? "POST",
      htu: path,
      bsh: createHash("sha256").update(opts.bodyForHash ?? body).digest("base64url"),
      jti: opts.jti ?? randomUUID(),
    })
      .setProtectedHeader(header)
      .setAudience("nexus-agent")
      .setIssuedAt(iat)
      .setExpirationTime(iat + 120)
      .sign(this.key.privateKey);
  }

  /** What the agent's loopback server returns to the console: the nonce, bound to the web origin that asked. */
  async attest(nonce: string, origin: string, opts: { iatOffset?: number } = {}) {
    const iat = Math.floor(Date.now() / 1000) + (opts.iatOffset ?? 0);
    return new SignJWT({ nonce, origin })
      .setProtectedHeader({ alg: "ES256", typ: "nexus-device+jwt", kid: this.id })
      .setAudience("nexus-device-attest")
      .setIssuedAt(iat)
      .setExpirationTime(iat + 60)
      .sign(this.key.privateKey);
  }
}

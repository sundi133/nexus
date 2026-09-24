import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM sealing for small secrets (e.g. TOTP seeds). `aad` binds the
 * ciphertext to its owner so a sealed value can't be moved to another row.
 */
export class Sealer {
  constructor(private readonly key: Buffer) {
    if (key.length !== 32) throw new Error("seal key must be 32 bytes");
  }

  seal(plaintext: Buffer, aad: string): Buffer {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(aad));
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), body]);
  }

  open(sealed: Buffer, aad: string): Buffer {
    const decipher = createDecipheriv("aes-256-gcm", this.key, sealed.subarray(0, 12));
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(sealed.subarray(12, 28));
    return Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]);
  }
}

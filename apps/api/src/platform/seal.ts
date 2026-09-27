import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM sealing for small secrets (TOTP seeds, provider credentials,
 * signing keys). `aad` binds a ciphertext to its owner so it can't be moved to
 * another row.
 *
 * Key rotation (ADR-024): ciphertexts carry the ID of the key that sealed
 * them — [0xA7][key id][iv 12][tag 16][body]. New secrets use the first
 * (current) key; older keys stay configured until `reseal` has re-encrypted
 * everything. Ciphertexts from before versioning ([iv][tag][body]) are read
 * with key 1.
 */

const MAGIC = 0xa7;

export type SealKeys = { id: number; key: Buffer }[];

/** "2:<base64>,1:<base64>" → keys, current first. */
export function parseSealKeys(s: string): SealKeys {
  return s
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => {
      const [id, b64] = p.split(":") as [string, string];
      const key = Buffer.from(b64 ?? "", "base64");
      const n = Number(id);
      if (!Number.isInteger(n) || n < 1 || n > 255) throw new Error(`Seal key id must be 1–255 (got ${id})`);
      if (key.length !== 32) throw new Error(`Seal key ${id} must be 32 bytes, base64-encoded`);
      return { id: n, key };
    });
}

export class Sealer {
  private readonly keys: Map<number, Buffer>;
  readonly currentId: number;

  constructor(keys: Buffer | SealKeys) {
    const list = Buffer.isBuffer(keys) ? [{ id: 1, key: keys }] : keys;
    if (!list.length) throw new Error("at least one seal key is required");
    for (const k of list) if (k.key.length !== 32) throw new Error("seal key must be 32 bytes");
    this.keys = new Map(list.map((k) => [k.id, k.key]));
    this.currentId = list[0]!.id;
  }

  seal(plaintext: Buffer, aad: string): Buffer {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.keys.get(this.currentId)!, iv);
    cipher.setAAD(Buffer.from(aad));
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([Buffer.from([MAGIC, this.currentId]), iv, cipher.getAuthTag(), body]);
  }

  open(sealed: Buffer, aad: string): Buffer {
    if (sealed[0] === MAGIC) {
      const key = this.keys.get(sealed[1]!);
      if (key) {
        try {
          return decrypt(key, sealed.subarray(2), aad);
        } catch (err) {
          // A legacy ciphertext can start with the marker byte by chance (1 in 256): fall through.
          if (!this.keys.has(1)) throw err;
        }
      } else if (!this.keys.has(1)) {
        throw new Error(`Sealed with key ${sealed[1]}, which isn't configured`);
      }
    }
    const legacy = this.keys.get(1);
    if (!legacy) throw new Error("Legacy sealed value but no key 1 is configured");
    return decrypt(legacy, sealed, aad);
  }

  /** Which key sealed this (1 for pre-versioning ciphertexts). */
  keyIdOf(sealed: Buffer, aad: string): number {
    if (sealed[0] === MAGIC && this.keys.has(sealed[1]!)) {
      try {
        decrypt(this.keys.get(sealed[1]!)!, sealed.subarray(2), aad);
        return sealed[1]!;
      } catch {
        /* legacy look-alike */
      }
    }
    return 1;
  }

  needsReseal(sealed: Buffer, aad: string) {
    return sealed[0] !== MAGIC || this.keyIdOf(sealed, aad) !== this.currentId;
  }
}

function decrypt(key: Buffer, data: Buffer, aad: string) {
  const decipher = createDecipheriv("aes-256-gcm", key, data.subarray(0, 12));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]);
}

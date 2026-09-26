import { hash, verify } from "@node-rs/argon2";

// OWASP-recommended Argon2id parameters (m=19 MiB, t=2, p=1). algorithm 2 = Argon2id.
const OPTS = { algorithm: 2 as const, memoryCost: 19456, timeCost: 2, parallelism: 1 };

export const MIN_PASSWORD_LENGTH = 12;

export const hashPassword = (pw: string) => hash(pw, OPTS);

// Verified against when the user doesn't exist, so response timing doesn't reveal valid emails.
const DUMMY = hash("nexus-timing-equalizer", OPTS);

export async function verifyPassword(stored: string | null, pw: string): Promise<boolean> {
  if (!stored) {
    await verify(await DUMMY, pw).catch(() => false);
    return false;
  }
  return verify(stored, pw).catch(() => false);
}

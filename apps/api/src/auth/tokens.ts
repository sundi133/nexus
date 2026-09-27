import { createHash, randomBytes, randomInt } from "node:crypto";

/**
 * Session tokens are opaque (`nxs_` + 256 random bits). Only the SHA-256 hash
 * is stored, so a database leak does not leak usable tokens, and revocation is
 * a single row update. (OAuth/OIDC tokens for third-party clients come later on
 * top of the same session model; see ARCHITECTURE §7.)
 */
export const newSessionToken = () => `nxs_${randomBytes(32).toString("base64url")}`;

export const hashToken = (token: string) => createHash("sha256").update(token).digest();

/** Three distinct two-digit numbers for push number matching; the first is the correct one. */
export function numberChoices(): { number: number; choices: number[] } {
  const set = new Set<number>();
  while (set.size < 3) set.add(randomInt(10, 100));
  const choices = [...set];
  const number = choices[0]!;
  return { number, choices: choices.sort((a, b) => a - b) };
}

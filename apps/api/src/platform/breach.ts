import { createHash } from "node:crypto";

/**
 * Breached-password check (SPEC AUTH-01) with Have I Been Pwned's range API:
 * only the first 5 hex chars of the SHA-1 leave the server (k-anonymity), and
 * responses are padded so their size reveals nothing. Fails open: if the
 * service is unreachable we don't block people from setting a password.
 */
export async function breachCount(base: string, password: string): Promise<number | null> {
  if (!base) return null;
  const sha1 = createHash("sha1").update(password).digest("hex").toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  try {
    const res = await fetch(`${base}/range/${prefix}`, { headers: { "add-padding": "true", "user-agent": "Votal-Nexus" }, signal: AbortSignal.timeout(3000) });
    if (!res.ok) return null;
    for (const line of (await res.text()).split("\n")) {
      const [s, n] = line.trim().split(":");
      if (s === suffix) return Number(n) || 0;
    }
    return 0;
  } catch {
    return null;
  }
}

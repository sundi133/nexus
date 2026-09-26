import { ed25519 } from "@noble/curves/ed25519.js";
import * as Crypto from "expo-crypto";

const toB64u = (bytes: Uint8Array) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const fromB64u = (s: string) => {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

/** A fresh Ed25519 key pair for this phone. The private key never leaves the device. */
export function generateDeviceKey() {
  const secret = Crypto.getRandomBytes(32);
  return { secretKey: toB64u(secret), publicKey: toB64u(ed25519.getPublicKey(secret)) };
}

/** Must match the server's signedMessage() in apps/api/src/auth/push.ts. */
export function signDecision(secretKey: string, challengeId: string, decision: "approve" | "deny", choice: number | null) {
  const msg = new TextEncoder().encode(`nexus-push-v1\n${challengeId}\n${decision}\n${choice ?? ""}`);
  return toB64u(ed25519.sign(msg, fromB64u(secretKey)));
}

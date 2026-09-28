import * as SecureStore from "expo-secure-store";
import type { OtpAccount } from "./totp";

/**
 * Everything the app keeps lives in the platform keystore (Keychain / Android
 * Keystore), readable only while the device is unlocked and never backed up
 * to other devices.
 */
const OPTS: SecureStore.SecureStoreOptions = { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY };

export type Pairing = {
  apiUrl: string;
  token: string; // mobile session token
  factorId: string; // this phone's push factor
  secretKey: string; // Ed25519 private key, base64url; signs approvals
  user: { email: string; displayName: string };
  orgName: string;
};

const KEY = "nexus.pairing.v1";

export async function loadPairing(): Promise<Pairing | null> {
  const raw = await SecureStore.getItemAsync(KEY, OPTS);
  return raw ? (JSON.parse(raw) as Pairing) : null;
}

export const savePairing = (p: Pairing) => SecureStore.setItemAsync(KEY, JSON.stringify(p), OPTS);
export const clearPairing = () => SecureStore.deleteItemAsync(KEY, OPTS);

// ---- Authenticator codes: each account's secret in its own keystore item, plus an index.
// They're kept when the phone is unpaired, like any authenticator app.

const OTP_INDEX = "nexus.otp.index.v1";
const otpKey = (id: string) => `nexus.otp.${id}`;

export async function loadOtpAccounts(): Promise<OtpAccount[]> {
  const ids = JSON.parse((await SecureStore.getItemAsync(OTP_INDEX, OPTS)) ?? "[]") as string[];
  const out: OtpAccount[] = [];
  for (const id of ids) {
    const raw = await SecureStore.getItemAsync(otpKey(id), OPTS);
    if (raw) out.push(JSON.parse(raw) as OtpAccount);
  }
  return out;
}

export async function saveOtpAccount(a: OtpAccount) {
  await SecureStore.setItemAsync(otpKey(a.id), JSON.stringify(a), OPTS);
  const ids = JSON.parse((await SecureStore.getItemAsync(OTP_INDEX, OPTS)) ?? "[]") as string[];
  if (!ids.includes(a.id)) await SecureStore.setItemAsync(OTP_INDEX, JSON.stringify([...ids, a.id]), OPTS);
}

export async function deleteOtpAccount(id: string) {
  await SecureStore.deleteItemAsync(otpKey(id), OPTS);
  const ids = JSON.parse((await SecureStore.getItemAsync(OTP_INDEX, OPTS)) ?? "[]") as string[];
  await SecureStore.setItemAsync(OTP_INDEX, JSON.stringify(ids.filter((x) => x !== id)), OPTS);
}

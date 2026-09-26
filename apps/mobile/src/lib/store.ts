import * as SecureStore from "expo-secure-store";

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

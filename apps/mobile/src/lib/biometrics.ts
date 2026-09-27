import * as LocalAuthentication from "expo-local-authentication";

/** Biometric (or device passcode) gate before acting as the person. */
export async function confirmWithBiometrics(prompt: string) {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const enrolled = hasHardware && (await LocalAuthentication.isEnrolledAsync());
  if (!enrolled) return true; // no biometrics set up: the device unlock already protects the keystore
  const r = await LocalAuthentication.authenticateAsync({ promptMessage: prompt, cancelLabel: "Cancel" });
  return r.success;
}

/** The catalog item a notification's link points at ("/access-requests?request=<id>"). */
export const requestIdFromLink = (link: string | null | undefined) => /[?&]request=([0-9a-f-]{36})/i.exec(link ?? "")?.[1] ?? null;

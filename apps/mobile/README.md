# Nexus Mobile

Authenticator and responder app (docs/SPEC.md §5.23). Expo SDK 57, Expo Router, TypeScript.
It uses the same generated API client as the web console (`@nexus/api-client`).

## Run it on your phone

1. Make the API reachable from your phone on the same Wi-Fi, so the pairing QR carries a working address. In the repo's `.env`:
   ```
   NEXUS_API_PUBLIC_URL=http://<your-mac-LAN-IP>:8080
   ```
   Then restart the API.
2. Start the app:
   ```
   pnpm --filter @nexus/mobile start
   ```
   Then open it in Expo Go (scan the terminal QR) or in a development build.
3. In the console, go to **My security → Add method → Nexus Mobile** and scan the pairing QR from the app.

## How approvals work

- **Pairing:** the app generates an Ed25519 key pair. The private key stays in the device keystore (`expo-secure-store`, this-device-only) and the public key is registered as a `push` factor.
- **Approving:** the console shows a number and the phone shows three. Tapping one triggers Face ID / Touch ID, then the app signs `nexus-push-v1\n{id}\n{decision}\n{choice}`. The server checks both the number and the signature.
- **"This wasn't me":** revokes the waiting sign-in and alerts the security team.

## Known limitations

- **Push delivery:** the API currently records pushes (`RecordingPushSender`) instead of calling APNs/FCM. The app polls every 3 seconds while open, so approvals still arrive. Real APNs/FCM delivery is next.
- **Expo Go:**
  - Android can't receive remote pushes there; use a development build (`npx expo run:android`).
  - Keystore items can't be biometric-locked. The app instead gates each signature with `expo-local-authentication`.
- **Hardware key:** planned upgrade is a non-exportable Secure Enclave / StrongBox key via a native module, plus DPoP-bound tokens (ARCHITECTURE §10.3).

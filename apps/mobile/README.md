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

## My requests

**My requests** (on the home screen) shows what you've asked for:
- **Active:** granted, with the end time and **Give back** to end it early.
- **Waiting:** who it's waiting on, and at which approval step, with **Withdraw**.
- **Earlier:** denied (with the approver's comment), withdrawn and ended requests.

**Ask for access** lists the catalog: apps, groups, software and blocked apps. Admin roles need a fresh sign-in check, so they're requested in the console. When a request is approved, denied or ends, the notification (or push) opens My requests.

## Authenticator codes

**Authenticator codes** (on the home screen) works as a standard authenticator app. Codes are made on the phone, so they work with no connection.

- **Nexus:** in the console, go to **My security → Add method → Authenticator app**, then scan its QR code with the app.
- **Other services:** scan any time-based authenticator QR code (`otpauth://totp/…`, with SHA-1, SHA-256 or SHA-512, 6–8 digits), or type a key.
- **Storage:** each account's secret is in the device keystore, on this device only, and kept if the phone is unpaired.
- **Tests:** `pnpm --filter @nexus/mobile test` checks the codes against RFC 6238's test vectors.

## Known limitations

- **Push delivery:** real pushes need a development or release build, plus APNs and FCM keys on the API: see [docs/MOBILE-PUSH.md](../../docs/MOBILE-PUSH.md). Without them the API logs pushes, and the app checks every 3 seconds while it's open.
- **Expo Go:**
  - Android can't receive remote pushes there, so the app doesn't load push support at all in Expo Go on Android. Notifications and approvals still appear in the app within a few seconds while it's open. For pushes, use a development build (`npx expo run:android`).
  - Keystore items can't be biometric-locked. The app instead gates each signature with `expo-local-authentication`.
- **Hardware key:** planned upgrade is a non-exportable Secure Enclave / StrongBox key via a native module, plus DPoP-bound tokens (ARCHITECTURE §10.3).

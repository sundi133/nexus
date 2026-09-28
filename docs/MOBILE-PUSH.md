# Nexus Mobile: real push notifications

Without push, Nexus Mobile checks for sign-in approvals, requests and notifications every few seconds, but only while it's open. With push, they reach the phone's lock screen even when the app is closed. That's what an authenticator needs.

Push needs three things: a real build of the app (not Expo Go), Apple's and Google's push keys on the API, and Firebase's config file in the Android build.

## What people get

Each notification carries only a category and an ID; the app fetches the details once opened. So no security data passes through Apple or Google, or shows on a lock screen.

| Kind | Android channel | iPhone |
|---|---|---|
| Sign-in approvals | **Sign-in approvals**: pops up and vibrates | Time-sensitive: breaks through Focus |
| Requests waiting for your approval | **Requests to approve**: high priority | Time-sensitive |
| Everything else (blocked apps, decisions on your requests, alerts) | **Updates** | Normal |

People can tune each Android channel in the phone's settings.

The app sends its push token to Nexus at every start, and again whenever the phone rotates it. So a phone first paired in Expo Go starts getting pushes as soon as it runs a real build. If the same phone is paired to another organization, its token moves with it.

## 1. Android: Firebase

1. In the [Firebase console](https://console.firebase.google.com), create a project (or use your Google Cloud project).
2. Add an **Android app** with package name `ai.votal.nexus`, and download **`google-services.json`**.
3. Put the file at `apps/mobile/google-services.json` for local builds. It's git-ignored. For EAS builds, upload it as a file secret named `GOOGLE_SERVICES_JSON`.
4. In Google Cloud → IAM → Service accounts, create a key for a service account with the **Firebase Cloud Messaging API Admin** role (or use the Firebase Admin SDK account). Give the API the whole JSON:
   ```
   NEXUS_FCM_SERVICE_ACCOUNT='{"type":"service_account","project_id":"…",…}'
   ```

## 2. iPhone: an APNs key

1. In Apple Developer → **Certificates, IDs & Profiles → Keys**, create a key with **Apple Push Notifications service (APNs)** enabled. Download the `.p8`; Apple offers it only once. Note the **Key ID** and your **Team ID**.
2. Make sure the App ID `ai.votal.nexus` has **Push Notifications** and **Time Sensitive Notifications** enabled.
3. Give the API:
   ```
   NEXUS_APNS_KEY=<contents of the .p8, or base64 of it>
   NEXUS_APNS_KEY_ID=ABC123DEFG
   NEXUS_APNS_TEAM_ID=XYZ987TEAM
   NEXUS_APNS_BUNDLE_ID=ai.votal.nexus
   NEXUS_APNS_ENV=sandbox        # development builds; production for TestFlight and the App Store
   ```

Restart the API. It logs a warning at start in production if either is missing.

## 3. Build the app

**On your own machine** (needs Android Studio for Android, Xcode for iPhone):
```bash
cd apps/mobile
npx expo run:android        # installs a development build on a connected phone or emulator
npx expo run:ios --device   # iPhone, signed with your Apple team
```

**With EAS** (Expo's build service, no local SDKs):
```bash
cd apps/mobile
npx eas build --profile development --platform android
npx eas build --profile development --platform ios
```
Install the build from the link EAS gives you. Then run `pnpm --filter @nexus/mobile start` as before; the development build connects to it like Expo Go did.

The `preview` profile makes an internal build without the developer menu, for testers. `production` is for the App Store and Google Play.

## 4. Check it

1. Open the development build and pair it (or open it if already paired: it registers its token).
2. Close the app, and lock the phone.
3. Sign in to the console with your password on a computer. A **Sign-in approval** notification reaches the phone's lock screen.
4. Tap it. The app opens on the approval, with the number to match.
5. Block an app on your laptop and open it (see [APP-REQUESTS.md](APP-REQUESTS.md)). An **Updates** notification arrives; tapping it opens **Request access**.

If nothing arrives, check what happened to that notification: `GET /v1/me/notifications/{id}/deliveries` (as the recipient) lists each channel with its result: sent, skipped by the person's preferences, or the error from Apple or Google. Without keys configured, the API's log shows `[push] …` lines instead.

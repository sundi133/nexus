# Android

Nexus manages Android phones and tablets with **Android Enterprise**, through Google's Android Management API:

- **Company phones** are fully managed.
- **Personal phones** get a work profile: work apps kept apart, and Nexus can't see or erase personal data.

Open **Devices → Android**.

## Connecting (once)

1. **Google Cloud:** create a project and enable the **Android Management API**. Create a service account with the **Android Management User** role, and download a JSON key.
2. **Nexus:** enter the project ID and upload the key. It's stored sealed, and Nexus only ever uses Google's own token endpoint with it. This needs an owner or admin (`org:manage`) and a recent MFA.
3. **Connect to Google:** sign in with the Google account that will own your Android enterprise. Google creates it and sends you back to Nexus, which finishes connecting and applies your policy.

## Policy

One policy applies to every enrolled device:

- **Passcode:** a minimum length (0 for none), on the device and on the work profile;
- **Lock after** so many minutes idle;
- **Only apps from Google Play:** no sideloading;
- **Camera:** on or off;
- **Apps:** installed automatically, available in the work Play Store, or blocked (by package name).

Changes are applied through Google straight away (`devices:enforce`, recent MFA). Devices pick them up within minutes.

## Enrolling

**Enroll a device** makes a token valid for 7 days:

- **Company phone:** on a new or factory-reset phone, tap the welcome screen six times, connect to Wi-Fi, and scan the QR code.
- **Personal phone:** send the person the link. Opening it on their phone adds the work profile.

Naming a person makes the device theirs once it enrolls.

## Devices

Nexus copies what Google reports:

- model, serial number, Android version and security patch level;
- company phone or work profile;
- whether it complies with the policy (and why not);
- when it last reported.

The copy is refreshed every hour, or with **Check now**. Devices removed at Google are removed here too.

| Action | Company phone | Work profile | Needs |
|---|---|---|---|
| Lock | ✓ | ✓ (the work profile) | `devices:actions` |
| Reboot | ✓ | — | `devices:actions` |
| Lost Mode on or off | ✓ | — | `devices:actions` |
| Erase / remove work profile | Factory reset | Removes the work profile; personal data stays | `devices:wipe`, the serial number typed to confirm |

Every action needs a reason and a recent MFA, and is audited (`android.command_sent`, `android.device_removed`).

## Limits

- **Status is polled**, hourly or on demand. Google's Pub/Sub notifications aren't used yet.
- **One policy for everyone:** no per-group policies, and no managed configurations for apps yet.
- **No conditional access from Android compliance yet.**
- **Tested against a simulated Google.** It covers service-account sign-in, sign-up, policies, enrollment tokens, devices and commands. Connecting for real needs your Google Cloud project, and real phones.

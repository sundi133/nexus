# Apple MDM (macOS)

Nexus can be the device management (MDM) server for your Macs, next to the Nexus agent on the same machines. **Devices → Apple MDM** enrolls Macs, sends MDM commands (lock, erase, restart, macOS updates, inventory), and escrows each Mac's **bootstrap token**. That token lets macOS install updates and give new accounts a FileVault SecureToken without a person's password.

## Setting it up

1. **Push certificate (once a year).** Apple wakes enrolled Macs through its push service (APNs) with a certificate issued to your organization. It's free.
   - **Make the request:** in Nexus, click **Make the request (CSR)**. Nexus generates the key, and it never leaves Nexus.
   - **Get it signed:** have the request signed by an **MDM vendor certificate**. That comes from the Apple Developer Enterprise Program (an "MDM CSR" certificate), or from your MDM vendor's signing service.
   - **Upload to Apple:** upload the signed request at Apple's Push Certificates Portal (identity.apple.com/pushcert) with a **company** Apple Account. Don't use a personal one: renewals need the same account.
   - **Finish in Nexus:** paste the certificate Apple issues into Nexus. Nexus checks it was made from its own request and records its topic and expiry.
   - **Renewing:** make a new request and choose **Renew** on the existing certificate at Apple. The topic must stay the same, because enrolled Macs only listen on the one they enrolled with, so Nexus refuses a certificate with a different topic. The old certificate keeps working until the new one is uploaded.
2. **Enrollment link.** Make a link (valid 1–365 days) and send it to people, or open it on each Mac. It downloads a profile. Installing it in **System Settings → Privacy & Security → Profiles** enrolls the Mac. Each download carries a **new device identity**, issued by your organization's own certificate authority. That CA is never installed as a trusted root, so it can't intercept anything.
3. **Done.** The Mac appears under **Enrolled Macs**, linked to its Nexus agent device by serial number. Nexus immediately asks for its details and security information (FileVault, SIP).

## What you can do

| Command | Permission | Notes |
|---|---|---|
| Refresh details, security info, installed apps | `devices:read` | |
| Install macOS updates | `devices:updates` | Installs everything available. Works without the user's password once the bootstrap token is escrowed |
| Restart | `devices:actions` | |
| Lock | `devices:actions` | Nexus generates a 6-digit PIN and shows it once. The Mac asks for it to unlock. Optional lock-screen message |
| Erase | `devices:wipe` | Type the serial number to confirm. PIN shown once |

Commands queue up and the Mac is woken through APNs. An offline Mac runs them when it next checks in. If a Mac is busy ("NotNow"), the command waits and goes again at its next check-in. Every command that changes a Mac needs a reason and a recent MFA. It's audited when sent and when the Mac answers (`apple_mdm.command_sent`, `apple_mdm.command_finished`).

## Security

- **Signed check-ins.** Every message from a Mac carries a CMS signature (`Mdm-Signature`) made with its device identity. Nexus accepts only identities it issued itself. Each identity is bound to one device (its UDID), so an enrolled Mac can't speak for another.
- **Sealed secrets.** Unlock tokens and bootstrap tokens are stored sealed. A bootstrap token is only ever given back to the Mac it came from.
- **PINs aren't kept.** Lock and erase PINs are masked in the database once the Mac has collected the command.
- **Unenrollment.** Removing the profile checks the Mac out. Nexus cancels its pending commands and stops accepting its messages.
- **Who can change it.** Enrollment links are limited in time and revocable. The push certificate is owner/admin only (`org:manage`), with MFA.

## Limits (not built yet)

- **Enrollment is manual.** There's no Apple Business Manager automated enrollment (ADE) yet: the Mac's user installs the profile from a link. ABM needs its own server token and an ABM account.
- **Profile shows as "Unverified".** The enrollment profile isn't signed yet, so macOS shows it that way.
- **Commands only.** No configuration profiles pushed yet (Wi-Fi, restrictions, FileVault enforcement), no declarative management, no user channel, and no app installation through MDM. For apps, use App deployment through the agent.
- **Macs only.** It's built and tested for macOS. iPhone and iPad aren't supported yet.
- **Tested against a simulated Mac.** It signs its messages the way Macs do. Enrolling a real Mac needs your push certificate and a real device.

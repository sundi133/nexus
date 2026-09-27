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

## Zero-touch enrollment (Apple Business Manager)

Macs bought through Apple or an authorized reseller can enroll themselves in Setup Assistant, before anyone signs in. Nobody has to click an enrollment link, and management can be made non-removable.

1. **Download Nexus's public key.** In **Apple MDM → Apple Business Manager**, click **Download public key**. The private key stays in Nexus.
2. **Add Nexus in Apple Business Manager.** Go to your name → **Preferences → Your MDM Servers → Add**, upload the key, save, then **Download Token** (a `.p7m` file).
3. **Upload the token in Nexus.** Choose the profile name, the IT support email and phone people see, and whether they may remove management.
   - Nexus opens the token with its key and checks it with Apple. It defines its enrollment profile, syncs the Macs assigned to this server, and assigns the profile to them.
4. **Assign Macs to the server in ABM.** New ones are picked up by the hourly sync (or **Sync now**) and assigned automatically.

In Setup Assistant, a Mac sends its signed machine info to this organization's enrollment URL. A Mac that isn't assigned to you in ABM gets nothing. An assigned Mac gets its own identity and enrolls like any other, then appears under **Enrolled Macs**.

## Configuration profiles

Under **Configuration profiles → Add profile**, build one from a template or upload your own `.mobileconfig`:
- **Templates:** screen lock, firewall, a Wi-Fi network, automatic macOS updates, and a login-window message.
- **Targeting:** every Mac, or the Macs of people in a group (through each Mac's Nexus agent user).

Nexus keeps each Mac in step:
- It installs a profile where it's missing or has changed, and removes it where it's no longer wanted.
- It reconciles when you save, when a Mac enrolls, when the Mac is linked to its user, and at each check-in.
- Each Mac's state (installing, installed, failed with the reason) is shown per profile.

Payloads are stored sealed, since they can contain Wi-Fi passwords. Profiles that would enroll the Mac in another MDM are refused. This needs `devices:enforce` and a recent MFA.

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

- **ADE machine info:** its signature is checked for integrity, but not yet chained to Apple's device CA. A serial number must also be assigned to you in ABM.
- **Profile shows as "Unverified".** The enrollment profile isn't signed yet, so macOS shows it that way.
- **Not yet supported:** signed profile uploads, declarative management, the user channel, FileVault recovery key escrow through MDM, and app installation through MDM. For apps, use App deployment through the agent.
- **Macs only.** It's built and tested for macOS. iPhone and iPad aren't supported yet.
- **Tested against a simulated Mac.** It signs its messages the way Macs do. Enrolling a real Mac needs your push certificate and a real device.

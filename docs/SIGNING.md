# Signing the agent for MDM rollout

MDMs push only signed agents:
- **macOS:** Jamf, Intune and Kandji install a `.pkg` silently only if it's signed with a **Developer ID Installer** certificate and notarized by Apple. Gatekeeper blocks everything else.
- **Windows:** Intune and Group Policy install an unsigned `.msi`, but SmartScreen, Smart App Control and many EDRs flag or block it. Sign both the binary and the `.msi` with **Authenticode**.

The build side is automated. You get the certificates once, which takes a few days because of identity checks, and store them as GitHub secrets. After that, every release is signed, notarized and verified by [`.github/workflows/agent-release.yml`](../.github/workflows/agent-release.yml).

| | Cost | Lead time | Who must do it |
|---|---|---|---|
| Apple Developer Program (organization) | $99/year | 1–7 days (D-U-N-S check) | Someone who can legally bind the company |
| Azure Trusted Signing (Windows, recommended) | ~$10/month | 1–5 days (identity validation) | An Azure subscription owner |
| or an OV code-signing certificate (DigiCert, Sectigo…) | $300–600/year | 1–5 days | Purchaser, and a company officer for verification |

## 1. Apple: Developer ID and notarization

### Enroll
1. Get a free [D-U-N-S number](https://developer.apple.com/enroll/duns-lookup/) for the legal entity, if it doesn't have one.
2. Enroll at [developer.apple.com/programs/enroll](https://developer.apple.com/programs/enroll/) **as an organization**, not as an individual (the certificate would carry a person's name). The enrolling Apple Account becomes the **Account Holder**.

### Create the two certificates
Only the Account Holder can create Developer ID certificates. Do this on a Mac:
1. **Keychain Access → Certificate Assistant → Request a Certificate From a Certificate Authority**. Enter your email, choose *Saved to disk*, and save the CSR.
2. At [Certificates, IDs & Profiles](https://developer.apple.com/account/resources/certificates/add), create a **Developer ID Application** certificate from that CSR, download it and double-click it.
3. Repeat for a **Developer ID Installer** certificate, using the same or a new CSR.
4. In Keychain Access, under *My Certificates*, export each one, with its private key, as a `.p12`. Use **one strong password for both**.
5. Note your **Team ID**: 10 characters, shown in each certificate's name and under Membership.

Keep the `.p12` files and the password in your password manager. If you lose them, you revoke and reissue. Installs that are already signed keep working, because notarization and timestamping cover them.

### Notarization key
1. At [App Store Connect → Users and Access → Integrations → App Store Connect API](https://appstoreconnect.apple.com/access/integrations/api), generate a **Team Key** with the *Developer* role.
2. Download the `.p8`; Apple lets you download it only once. Note the **Key ID** and the **Issuer ID**.

## 2. Windows: Authenticode

Since June 2023, publicly trusted code-signing keys must live in hardware (an HSM or a token), so you can no longer download a `.pfx`. Choose one of the following.

### a. Azure Trusted Signing (recommended)
It's cheap, it has no hardware, and Microsoft's own CA builds SmartScreen reputation quickly.
1. In an Azure subscription, create a **Trusted Signing account**. Note the region's endpoint, e.g. `https://eus.codesigning.azure.net` for East US.
2. Under the account's **Identity validation**, start a *Public* validation for the organization. Microsoft checks the legal entity, which takes a few business days. Availability depends on where the organization is registered: the US, Canada, the EU and the UK at the time of writing.
3. When the validation is approved, create a **Certificate profile** of type *Public Trust* that uses it.
4. In **Entra ID → App registrations**, create an app, e.g. `nexus-release-signing`, and add a **client secret**. Note the tenant ID, client ID and secret.
5. On the Trusted Signing account, go to **Access control (IAM)** and give that app the role **Trusted Signing Certificate Profile Signer**.

### b. A certificate from a CA, in DigiCert KeyLocker
Buy an OV (or EV) code-signing certificate with **KeyLocker** delivery. In DigiCert ONE you then get:
- an API key;
- a client authentication certificate (`.p12`) and its password;
- the key pair alias.

`sign-windows.sh` supports this too, through the `NEXUS_DIGICERT_*` variables, if you run releases by hand. The workflow uses Trusted Signing or a `.pfx`.

### c. An older `.pfx`
If you already have an exportable certificate issued before the June 2023 rule, set `WINDOWS_CERT_PFX_B64` and `WINDOWS_CERT_PASSWORD`.

## 3. The release key

Agents trust only updates signed with the Ed25519 release key compiled into them. Generate it once, offline:

```bash
cd agent && go run ./cmd/nexus-release keygen --out ~/nexus-release-key
```

Store `release.key` in your password manager. Every future update depends on it, and losing it means reinstalling agents. The API needs `release.pub` in `NEXUS_AGENT_RELEASE_KEYS`.

## 4. GitHub secrets

In the repository, go to **Settings → Secrets and variables → Actions → New repository secret**. Better still, put them in an Environment with required reviewers. Base64 files with `base64 -i FILE | pbcopy`.

| Secret | Value |
|---|---|
| `NEXUS_RELEASE_KEY_B64` | `base64 -i release.key` |
| `NEXUS_RELEASE_PUB` | contents of `release.pub` |
| `APPLE_DEVELOPER_ID_APP_P12_B64` | base64 of the Developer ID Application `.p12` |
| `APPLE_DEVELOPER_ID_INSTALLER_P12_B64` | base64 of the Developer ID Installer `.p12` |
| `APPLE_P12_PASSWORD` | the `.p12` password |
| `APPLE_TEAM_ID` | e.g. `A1B2C3D4E5`; every signature is checked against it |
| `APPLE_NOTARY_KEY_P8_B64` | base64 of the `.p8` |
| `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID` | from App Store Connect |
| `TRUSTED_SIGNING_ENDPOINT` | e.g. `https://eus.codesigning.azure.net` |
| `TRUSTED_SIGNING_ACCOUNT`, `TRUSTED_SIGNING_PROFILE` | account and certificate profile names |
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | the signing app registration |

Only the release key is required. When Apple or Windows secrets are missing, the workflow builds unsigned for that platform and says so in a warning.

## 5. Cut a release

**Actions → Agent release → Run workflow**, with a version such as `1.0.0`, or push a tag `agent-v1.0.0`. The workflow runs these jobs:
1. **build (macOS runner):**
   - builds every platform;
   - codesigns the macOS binaries (hardened runtime, secure timestamp) and Authenticode-signs the Windows binaries;
   - *then* writes the Ed25519 release signature, so self-updates carry the same signed bytes as the installers;
   - builds the `.pkg` (signed, notarized, stapled), `.deb` and `.rpm`;
   - runs `verify-signatures.sh`, which fails the release if a signature, the Team ID, the hardened runtime, the timestamp, notarization or Gatekeeper acceptance is missing.
2. **msi (Windows):** builds the `.msi` from the signed binaries.
3. **publish:** signs the `.msi`, verifies it, and creates a **draft** GitHub release with every installer and the release archive for `NEXUS_AGENT_RELEASES_DIR`.
4. **windows-trust:** on a clean Windows machine, checks the chain with `Get-AuthenticodeSignature`, installs silently, checks the installed binary's signature, and uninstalls.

Review the draft release and publish it. To serve updates, unpack the archive into `NEXUS_AGENT_RELEASES_DIR/<version>` on the API host.

To check a build yourself: `agent/scripts/verify-signatures.sh agent/dist/releases/1.0.0 agent/dist/installers --mac --windows`.

## 6. Deploying with an MDM

### Jamf Pro (macOS)
1. **Enrollment token:** a policy with a script that runs *before* the package and writes the file:
   ```bash
   install -d -m 700 "/Library/Application Support/Nexus"
   printf 'server=%s\ntoken=%s\n' "https://api.nexus.corp.example.com" "$4" > "/Library/Application Support/Nexus/enroll.conf"
   chmod 600 "/Library/Application Support/Nexus/enroll.conf"
   ```
   Pass the `nxe_…` token as parameter 4, so it isn't in the script body. The package's postinstall enrolls and deletes the file.
2. **Package:** upload `nexus-agent-<version>.pkg` and add it to the same policy.
3. **Background item notice** (macOS 13+): deploy a *Managed Login Items* (`com.apple.servicemanagement`) configuration profile with a rule of type **Team Identifier** set to your `APPLE_TEAM_ID`. Users then don't see "Background item added", and can't switch the agent off in System Settings.

### Intune (macOS)
**Apps → macOS → Add → macOS app (PKG)**, upload the `.pkg`. Deliver `enroll.conf` first with a **shell script** (Devices → macOS → Scripts) like the one above, running as root, with the token inline. Intune scripts aren't parameterised, so limit the script's assignment to the pilot group, and use a short-lived token. Add the same Managed Login Items rule as a **Settings catalog** profile.

### Intune (Windows)
**Apps → Windows → Add → Line-of-business app**, upload `nexus-agent-<version>-x64.msi`, with command-line arguments `SERVER=https://api.nexus.corp.example.com TOKEN=nxe_…`. For arm64 devices, add the `-arm64.msi` as a second app assigned to an arm64 device filter. The token is visible to Intune admins, so use a dedicated enrollment token with an expiry and revoke it after rollout.

### Group Policy (Windows)
Assign the `.msi` from a share in a GPO under *Computer Configuration → Software Installation*, with a transform or `enroll.conf` pre-staged in `C:\ProgramData\Nexus` by a startup script.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Developer ID Application and Installer identities not found` | A `.p12` was exported without its private key, or both were exported with different passwords |
| Notarization `Invalid`, log mentions hardened runtime or timestamp | The binaries weren't codesigned with `--options runtime --timestamp`. `release.sh` does this when `NEXUS_CODESIGN_IDENTITY` is set |
| `Trusted Signing needs …` / HTTP 403 from the endpoint | A missing secret, or the app lacks the *Certificate Profile Signer* role (role assignments take a few minutes) |
| Windows says the signature is `UnknownError` / `NotTrusted` | Self-signed or test certificate. Only a public CA or Trusted Signing is trusted |
| SmartScreen still warns on a signed `.msi` | Reputation builds with installs. Trusted Signing and EV certificates start with better reputation |

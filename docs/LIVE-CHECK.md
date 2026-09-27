# Live vendor check

Nexus's connectors are tested against protocol fakes. Real tenants have quirks the fakes don't: missing mail attributes, guest accounts, placeholder serial numbers, throttling, permissions that look granted but aren't. The live check runs **Nexus's production connector code** against your tenants and writes a report you can send back.

- **Read-only** against directories and MDMs. It never writes to Entra, Google, AD, Intune or Jamf.
- **Opt-in for anything that notifies.**
  - `--page` triggers one `[TEST]` incident in PagerDuty or Opsgenie, then acknowledges and resolves it.
  - `--send-events` delivers one test event to Sentinel or S3.
- **Production rules.** It refuses private and internal addresses, as a production server does, unless you allow them. If something only works with `LIVE_ALLOW_PRIVATE=true`, that's a finding too.
- **Redacted report.** It contains counts, percentages, email domains, hostnames and findings. Emails, GUIDs, LDAP DNs and every configured secret are replaced with short salted hashes (a new salt each run). Read the report before you send it.

## Run it

From a checkout (Node 22+ and pnpm):
```bash
cp live-check.env.example live-check.env        # git-ignored; fill in what you have
pnpm install
pnpm --filter @nexus/api live-check              # add --page and/or --send-events when ready
```

On the Nexus server, from the image you deployed. This is the network path that matters for on-prem AD and Jamf:
```bash
docker run --rm --env-file live-check.env votal/nexus-api:local node dist/cli/live-check.js --out=- > live-check-report.json
```
For files such as a Google key or an LDAP CA, mount them (`-v $PWD/google-key.json:/keys/google.json:ro`) and point `LIVE_GOOGLE_KEY_FILE` at the mounted path.

Run one check at a time with `--only=entra_directory,intune`. The exit code is 1 when a check fails.

Each check ends in one of these states:

| Result | Meaning |
|---|---|
| `ok` | Worked, and nothing unusual in the data |
| `warn` | Worked, with findings: data a pilot will trip over (see below) |
| `fail` | Didn't work. The error is the vendor's own message, redacted |
| `skipped` | Not configured, or it notifies people and you didn't pass `--page` / `--send-events` |

## Getting a test tenant

Use a test tenant first if you have one; then run against production with read-only credentials made for this, and delete them afterwards.

### Microsoft Entra ID and Intune
- **Tenant:**
  - a free Entra ID tenant comes with any Azure account;
  - for Intune, start a Microsoft 365 E5 or Intune Plan 1 trial in the Microsoft 365 admin center (30 days);
  - enroll one Windows VM or Mac so there's a device.
- **App registration** (Entra admin center → App registrations → New):
  - Add a client secret.
  - Under **API permissions**, add Microsoft Graph **Application** permissions:
    - `User.Read.All`, `Group.Read.All`, `GroupMember.Read.All` (directory);
    - `DeviceManagementManagedDevices.Read.All` (Intune).
  - Click **Grant admin consent**. It's easy to miss: without it, the token works but every read fails with 403.
- Put the tenant ID, client ID and secret in `LIVE_ENTRA_*`, and set `LIVE_INTUNE=true` to reuse the app for Intune.
- **Sign-in metadata:**
  - `LIVE_OIDC_ISSUERS=https://login.microsoftonline.com/<tenant ID>/v2.0`;
  - `LIVE_SAML_METADATA_URLS=https://login.microsoftonline.com/<tenant ID>/federationmetadata/2007-06/federationmetadata.xml`.

### Okta
- **Tenant:** a free Integrator account at developer.okta.com.
- `LIVE_OIDC_ISSUERS=https://<your org>.okta.com`, or `https://<your org>.okta.com/oauth2/default` if you use the default authorization server.
- For SAML, create a SAML app and use its **Metadata URL**.
- SCIM from Okta to Nexus needs a running Nexus (section 4a of the [pilot guide](PILOT.md)); the live check doesn't cover it.

### Google Workspace
- **Tenant:** a 14-day Business trial.
- **Service account** (Google Cloud console): create a JSON key.
- **Domain-wide delegation:** in the Admin console, go to **Security → API controls → Domain-wide delegation** and add the service account's client ID with these scopes:
  `https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.group.member.readonly`
- Set `LIVE_GOOGLE_ADMIN_EMAIL` to a super admin, and `LIVE_GOOGLE_KEY_FILE` to the key's path.

### Active Directory
- **Tenant:** a Windows Server evaluation VM (180 days) promoted to a domain controller, or your real domain.
- **Service account:** create a plain user account; Domain Users can read the directory.
- Prefer `ldaps://dc.corp.example.com:636`, which needs a certificate on the DC (AD CS or your internal CA). Put that CA's PEM in `LIVE_LDAP_CA_FILE`.
- For a DC on a private network, set `LIVE_ALLOW_PRIVATE_DIRECTORY=true`, or run the check from the Nexus server as shown above.

### Jamf Pro
- **Tenant:** a Jamf Pro trial (through Jamf sales) or your instance.
- Under **Settings → API roles and clients**:
  - create a role with **Read Computers**;
  - create a client with that role, enable it, and generate a secret.
- The check also tells you whether lock and wipe would work: they need the computers' management IDs.

### PagerDuty and Opsgenie
- **PagerDuty:** the free plan works. Create a service, then go to **Integrations → Events API v2** and copy the integration key into `LIVE_PAGERDUTY_ROUTING_KEY`.
- **Opsgenie:** go to **Settings → Integrations → API** and copy the key into `LIVE_OPSGENIE_API_KEY`. For an EU account, set `LIVE_OPSGENIE_REGION=eu`. Atlassian is winding down Opsgenie in favour of Jira Service Management, so prefer PagerDuty for new setups.
- Run with `--page`, then check that the incident arrived and closed on its own.

### Microsoft Sentinel and S3
- **Sentinel:** the console's **Settings → Integrations → Sentinel** walks through the setup (a data collection endpoint and rule, plus an app with *Monitoring Metrics Publisher* on the rule). Use the same values in `LIVE_SENTINEL_*`. Rows appear in the workspace after a few minutes.
- **S3:** create a bucket and an IAM user allowed `s3:PutObject` on the prefix. The test object goes under `<prefix>/_nexus-test/`.

## Beyond the check

The check covers what can run unattended. During the pilot, also try the following, and send what you see:
1. **Sign-in:** under **Settings → Single sign-on**, use **Test sign-in** for each IdP. It shows the claims that arrived. Send the claim *names*, and whether `email`, `groups` and `amr` were present, not their values. Entra ID v2.0 ID tokens may carry no `amr` claim, so Nexus can't tell the IdP did MFA; please check this one.
2. **SCIM:** after Okta or Entra provisions the pilot group, check **Directory sync → SCIM** for rejected requests.
3. **Device rollout:** install the agent through Intune or Jamf on one machine each ([SIGNING.md](SIGNING.md#6-deploying-with-an-mdm)). Then check under **Device management** that the device shows as matched.

## What the findings mean

| Finding | What happens in Nexus | What to do |
|---|---|---|
| People have no email / only `.onmicrosoft.com` | Not created, or created with the wrong address | Set the `mail` attribute, or scope sync to licensed users |
| People share an email | The second one is skipped | Fix the duplicate in the directory |
| `#EXT#` guest-style addresses | Created with an unusable address | Exclude guests or B2B members from the synced group |
| Group members aren't among the people read | Membership partially applied | Usually guests or people outside the sync scope: expected, but check the count |
| Placeholder serial / devices share a serial | That device is never matched to its MDM record; the "managed and compliant" check fails with a clear reason | Fix the BIOS serial (common on white-box PCs and cloned VMs), or leave that policy off for those devices |
| No compliance verdict | Treated as *managed*, not *compliant* | Assign a compliance policy in Intune |
| Compliance state Nexus doesn't know | Treated as unknown | Send us the value; we'll map it |
| Devices' users aren't in the directory | Device ownership won't resolve | Usually UPN ≠ mail; tell us which attribute your MDM uses |
| No management IDs (Jamf) | Lock and wipe through Jamf fail | The API role can't see them: review its computer and MDM privileges, then run the check again |
| Issuer mismatch errors | Sign-in can't be configured | Follow the message; it names the exact issuer to use |

## Found so far against live vendors

These came from running the check against live endpoints while building it:
- **Entra ID multi-tenant endpoint:** `…/common/v2.0` publishes its issuer as `https://login.microsoftonline.com/{tenantid}/v2.0`, a template. Nexus refuses it, as it must, and now says to use the tenant's own issuer.
- **Entra ID v1 endpoint:** a URL without `/v2.0` reports `https://sts.windows.net/<tenant>/` as its issuer. The error now gives the right v2.0 URL.
- **PKCE:** Entra ID doesn't advertise PKCE support in its discovery document, but supports it. Nexus always sends PKCE, so no change was needed.
- **Entra app IDs:** Entra client IDs are GUIDs, not always RFC 4122 UUIDs. Nexus now accepts any GUID for Entra, Intune and Sentinel app IDs.
- **Serial matching:** placeholder serials such as `To Be Filled By O.E.M.` and shared VM serials could attach another machine's MDM verdict to a device, and choose the wrong target for MDM lock or wipe. Matching now requires a real serial that is unique on both sides.

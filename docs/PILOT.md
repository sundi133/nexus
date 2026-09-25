# Piloting Votal Nexus in your enterprise

This guide takes you from a fresh server to a working pilot that uses your own identity provider, directory, devices and AI agents. Plan for about half a day, most of it spent in your IdP and MDM consoles. Read [Known limits](#known-limits) before you start, so the pilot has the right scope, and run the [live vendor check](LIVE-CHECK.md) against your tenants first. It finds most vendor quirks in minutes.

## 1. What you need

| | |
|---|---|
| Server | One Linux VM: 4 vCPU, 8 GB RAM, 50 GB disk, Docker Engine 24+ with the compose plugin |
| DNS | Two names pointing at the VM, e.g. `nexus.corp.example.com` (console) and `api.nexus.corp.example.com` (API, agents, SCIM, MCP gateway) |
| Network | Inbound 443 and 80 (Let's Encrypt). Outbound HTTPS to your IdP, Let's Encrypt, `api.pwnedpasswords.com`, and any webhook, SIEM or MCP servers you connect |
| Email | An SMTP relay Nexus can send through (invitations, password resets, alerts) |
| People | An owner (you), a second admin to test roles, and 5–20 pilot users in one IdP group |

Start with a **separate pilot group** in your IdP. Don't point Nexus at your whole company on day one.

## 2. Deploy

```bash
git clone https://github.com/sundi133/nexus.git && cd nexus
cp deploy/compose/prod.env.example deploy/compose/prod.env
```

Fill in `deploy/compose/prod.env`:

```bash
openssl rand -base64 32                         # for each password and the metrics token
echo "1:$(openssl rand -base64 32)"             # NEXUS_SEAL_KEYS: keep a copy in your password manager
```

- `NEXUS_CONSOLE_HOST` and `NEXUS_API_HOST`: the two DNS names.
- `NEXUS_SIGNUP=first`: the default. Only the first organization (yours) can be created; after that, sign-up is closed.
- `NEXUS_ALLOW_PRIVATE_DIRECTORY=true` only if this server should talk to your domain controllers directly (see 4c).

```bash
docker compose -f deploy/compose/docker-compose.prod.yml --env-file deploy/compose/prod.env up -d --build
curl -s https://api.nexus.corp.example.com/readyz       # {"ok":true,"schema":"…"}
```

Production refuses to start on unsafe settings and lists every problem at once. Fix them and run `up` again.

Open `https://nexus.corp.example.com`, sign up with your work email (this makes you the owner), then:
1. Enroll MFA. A passkey is best.
2. Go to **Settings → Organization** and apply the secure baseline: MFA for everyone, 12-hour sessions, owners confirm with a passkey.
3. Create a **break-glass** owner (e.g. `emergency@corp.example.com`) on its user page, print and seal its password, and keep it offline.
4. Verify your email domain under **Settings → Organization → Domains** (a DNS TXT record).

## 3. Sign-in through your IdP

**Settings → Single sign-on → Add identity provider.**

- **Entra ID or Okta over OIDC:** register an app with redirect URI `https://nexus.corp.example.com/federation/oidc/callback`, then paste the issuer, client ID and secret.
- **ADFS, Entra ID or Okta over SAML:** give the IdP the SP metadata URL shown in Nexus, then paste the IdP's metadata.

Click **Test sign-in**. It shows exactly which claims arrived and which account they map to. Leave "require the IdP" off until the pilot group has signed in successfully; your break-glass account always keeps its password.

Only owners can change IdP trust settings, deliberately: whoever controls the IdP can sign in as anyone it vouches for.

## 4. Bring in people (pick one)

**a. Your IdP pushes (Okta, Entra ID, JumpCloud): recommended.** Go to **Directory sync → Set up SCIM**, copy the URL and token into your IdP's provisioning settings, and assign only the pilot group. New hires appear within minutes and leavers are suspended. A burst of deactivations pauses until an admin approves it.

**b. Nexus reads Google Workspace or Entra ID.** Go to **Directory sync → Connect a directory**. Test the connection, scope it to the pilot group, preview, then sync.

**c. Active Directory on-prem.**
- **This server can reach a domain controller:** set `NEXUS_ALLOW_PRIVATE_DIRECTORY=true`, then **Connect a directory → Active Directory / LDAP**. Use `ldaps://dc1.corp:636` and a read-only service account, and paste your internal CA if needed. Optionally turn on sign-in with the directory password (admins always keep a Nexus password).
- **It can't:** set up SCIM (4a), then run the on-prem connector inside your network every 15 minutes. See [packages/cli/README.md](../packages/cli/README.md#on-prem-active-directory--ldap-connector) for `nexus directory push -c connector.yaml`. Try `--dry-run` first.

Every sync shows a preview before it changes anything. Sync never changes an admin's email and never suspends your last owner.

## 5. Devices

Create an enrollment token under **All devices → Add devices** (or the **Enrollment tokens** tab).

| Platform | Pilot install |
|---|---|
| Linux | `sudo dpkg -i nexus-agent_*.deb`, then `sudo nexus-agent install --server https://api.nexus.corp.example.com --token nxe_…` |
| macOS | `sudo installer -pkg nexus-agent-*.pkg -target /`, then the same `install` command |
| Windows (admin PowerShell) | `msiexec /i nexus-agent-*-x64.msi /qn SERVER=https://api.nexus.corp.example.com TOKEN=nxe_…` |

Build the installers with `pnpm agent:release <version>`; the Windows `.msi` is built on Windows (see [agent/README.md](../agent/README.md#releasing)).

For silent MDM rollout (Jamf, Intune), the agent must be signed with your Apple Developer ID and a Windows code-signing certificate. [SIGNING.md](SIGNING.md) walks through getting them (a few days of identity checks), the GitHub secrets, and the *Agent release* workflow, which signs, notarizes and verifies every build. Until then:
- **macOS:** installing from the command line works, but double-clicking is blocked by Gatekeeper, and MDMs won't push the package silently.
- **Windows:** SmartScreen warns.
- **Scope:** keep the pilot to hand-installed machines.

Then:
1. Set **Device policies** to *audit* mode first and look at what would fail.
2. Connect **Intune or Jamf** under **Device management** so their compliance verdicts count.
3. Add a **Conditional access** policy in *report-only* mode ("require a compliant device for app X") and read its 7-day impact before you enforce it.

## 6. Apps

Go to **Applications → Add app**: pick one from the catalog or add any SAML/OIDC app, and assign it to the pilot group. The pilot group can then sign in to it through Nexus, and SCIM provisioning to the app works if the app supports it.

## 7. AI agents and MCP

1. **Agents → Register agent**, with an owner. Prefer a workload identity credential (GitHub Actions, Kubernetes) over a secret.
2. **MCP servers → Add server**, e.g. your GitHub or internal MCP server with a scoped token. Review the discovered tools, approve the read-only ones, and add a permission rule (e.g. agents tagged `support` may use read tools on `repo in [acme/web]`).
3. Point your agent at the gateway URL shown on the server's page, with a Nexus token from the client credentials grant (the curl command is on the agent's page).
4. Watch **Agents → activity** and **Audit log**. Try a denied call, and the **Suspend now** kill switch.

## 8. SecOps

- **Alerts:** the default rules are on. Connect PagerDuty or Opsgenie under **Alerts → On-call** with *critical only*, then **Send test**.
- **SIEM:** go to **Settings → Integrations** and stream the audit log to Splunk, Datadog, Sentinel, S3 or a webhook.
- **Reports:** MFA coverage, admin access, dormant accounts and device compliance, with CSV export.
- **Audit log:** it shows the hash chain's status. Compare the latest digest with the `audit.sealed` events in your SIEM.
- **Config as code:** export the configuration with `nexus config export` (API key with `org:manage`) and keep it in Git.

## 9. Operate

| Task | How |
|---|---|
| Backups | `deploy/ops/backup.sh /backups` nightly (cron); test a restore with `deploy/ops/restore-test.sh`. Keep `NEXUS_SEAL_KEYS` with the backups: without it, stored secrets can't be decrypted |
| Updates | `git pull && docker compose … up -d --build`. Migrations run before the API starts; `/readyz` stays unhealthy until the schema matches |
| Monitoring | Prometheus scrapes `https://api…/metrics` with `Authorization: Bearer $NEXUS_METRICS_TOKEN` (blocked on the public edge by default; scrape from inside); JSON logs go to Docker |
| Scaling | The compose file runs two API replicas and a worker. Rate limits and jobs are shared through Postgres, so adding replicas is safe |
| Leaving the pilot | Disconnect directories and the IdP in the console, then `docker compose … down -v` deletes everything, including the database volume |

## 10. Pilot test plan

Tick these off with your pilot group; each item is a real enterprise scenario.

1. A pilot user signs in through your IdP, and the IdP's MFA is recognised.
2. A new user added to the IdP group appears in Nexus and gets app access without anyone touching Nexus.
3. A user removed from the group is suspended, signed out everywhere, and deactivated in provisioned apps.
4. Offboard someone with a future date and watch it happen on the day.
5. A helpdesk admin scoped to one group can't see or touch anyone else (or any admin).
6. A laptop fails a device policy, the user is told what to fix, and conditional access blocks the app once it's enforced.
7. An access request with manager approval grants 8 hours of access, which then expires on its own.
8. An access review over one app: revoke someone and confirm they lose access when it closes.
9. An AI agent calls an allowed tool through the gateway, is refused a disallowed one, and is cut off by **Suspend now** within seconds.
10. Change an MCP tool's description upstream: it drops out of service until re-approved.
11. Ten wrong passwords for one account raise an alert and page your on-call test service.
12. The audit log verifies, and its digest matches your SIEM.
13. Restore last night's backup to a scratch database with `restore-test.sh`.

## Known limits

- **Not externally audited:** no penetration test or SOC 2 yet. An internal adversarial review found and fixed privilege-escalation paths (IdP swap, SCIM on owners, help desk on admins, MCP condition bypass, DNS rebinding), but treat this as pre-audit software: keep the pilot group small and don't make Nexus the only gate on crown-jewel systems yet.
- **Agent signing needs your certificates:** the pipeline is built and verified, but builds are unsigned until you add an Apple Developer ID and a Windows signing identity ([SIGNING.md](SIGNING.md)).
- **Barely tested against real vendors:** Entra ID, Okta, AD, Intune, Jamf, PagerDuty, Opsgenie and Sentinel are covered by protocol tests and local fakes. Only the public Entra ID, Okta and Google sign-in metadata has been checked live. Before the pilot, run the [live vendor check](LIVE-CHECK.md) against your tenants and send the report back.
- **Single host:** Postgres runs on the same VM (see [OPERATIONS.md](OPERATIONS.md) for a managed database), and audit data stays in Postgres. That's fine for a pilot of hundreds of users.
- **Not built yet:** organization data export and deletion (use `down -v`), a Terraform provider, MCP resources and prompts, content guardrails, and letting people connect their own MCP clients (agents only).

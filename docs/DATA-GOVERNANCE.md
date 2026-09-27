# Data governance

This covers the questions a security, privacy or legal review asks:
- what Nexus stores and where;
- how it's protected;
- how long it's kept;
- how to get it out;
- how to delete a person or the whole organization.

## Where the data lives

Everything is in the deployment's Postgres database, in the region you run it. There are no other data stores and no subprocessors: Nexus sends data out only to services you connect (your identity providers, apps, SIEM, archive, on-call, email and push providers).

**Tenant isolation:** each organization's rows are separated by row-level security, enforced by the database for the application's role, which can't bypass it. CI checks that every table is covered.

## How it's protected

| Layer | How |
|---|---|
| In transit | TLS to the console, the API and the database |
| At rest | The database's storage encryption. On a managed database, use a customer-managed KMS key (for example AWS KMS on RDS, CMEK on Cloud SQL, or Azure Key Vault) to control and revoke it |
| Secrets in the database | Sealed with AES-256-GCM before they're stored: directory and MDM credentials, webhook and SIEM secrets, signing keys, TOTP seeds. The seal keys come from your secret manager (`NEXUS_SEAL_KEYS`, rotated with `reseal`; see [OPERATIONS.md](OPERATIONS.md#key-rotation-seal-keys)). Passwords, API keys and tokens are stored only as hashes |
| Password manager | End-to-end encrypted in the browser. Nexus stores only ciphertext and can't decrypt it ([PASSWORDS.md](PASSWORDS.md)) |
| Access | Roles and permissions, step-up MFA for sensitive actions, everything audited in a tamper-evident log ([SECURITY.md](SECURITY.md)) |

## Retention

**Settings → Organization → Data and privacy** lists what's kept and for how long. So does `GET /v1/org/data-retention`. An hourly job applies the rules in batches.

| Data | Kept |
|---|---|
| Audit log | Your setting: 30 days to 10 years, default 365 days. Never removed before your SIEM or archive has it |
| Process events from devices | 7 days |
| Sessions (IP address, browser) | 30 days after they end |
| Invitations | 30 days after they're accepted, revoked or expire |
| Notification inbox | 180 days |
| Notification, SIEM and webhook delivery logs | 90 and 30 days |
| Alert rule matches; block-rule events | 90 days |
| Device commands | 90 days after they finish |
| Live device queries | 30 days after they expire |
| Sign-in codes and challenges | 1 day after they expire |
| Background job records | 7 days (30 days if they failed) |
| Everything else (people, groups, apps, devices, policies) | Until you delete it, or the organization |

**Backups** follow the operator's policy, for example a 7–35 day point-in-time recovery window. Deleted data leaves the backups when they expire.

## Getting your data out

- **Everything:**
  - Use **Data and privacy → Export all data**, or `GET /v1/org/export` (permission `data:export`; owners and admins, or an API key with that scope).
  - It's gzipped JSON lines from one consistent snapshot: a manifest, then each table's columns and rows, then an `end` line with row counts. If the `end` line is missing, the download was cut short.
  - Secrets (password hashes, sealed credentials, keys, token hashes) are left out, and each table lists what was left out.
  - Exports are streamed, so any size works, and each one is recorded in the audit log.
- **One person (privacy access request):**
  - Use **the person → Download data**, or `GET /v1/users/{id}/data-export`.
  - It includes their profile, group and role memberships, MFA factors and sessions (metadata only), devices, requests, reviews and notifications, and the audit events where they're the actor or the target.
  - It's recorded in the audit log.

## Erasing a person

Use **the person → Erase…**, or `POST /v1/users/{id}/erase`. It needs the `users:erase` permission, which owners and admins have and help desk doesn't, a recent MFA, and the person's email typed to confirm.

- **Before:**
  - The person must be suspended or offboarded, so their access everywhere is gone.
  - Their accounts in provisioned apps must be deactivated.
  - Break-glass accounts and your own account can't be erased.
- **Deleted:** their profile, memberships, roles, MFA factors, sessions, recovery codes, push registrations, requests, review items and notifications.
- **Kept without them:** records that belong to the organization, such as devices (unassigned), policies they created and decisions they made.
- **Kept as they are:** audit events about them. The audit log is append-only and hash-chained, and it's kept to meet security and legal obligations (GDPR Art. 17(3)(b) and (e)). It ages out with your audit retention. The erasure itself is audited by ID only, never by email.
- **Directory-managed people:** if a directory sync created them, remove them from the directory too, or the next sync adds them again. The response says so (`directory_managed`).

## Deleting the organization

Use **Data and privacy → Delete organization…**, or `POST /v1/org/deletion`. Only owners can do it, with a recent MFA (a passkey if you require one for owners), and never with an API key. The organization's name must be typed to confirm.

1. Owners and admins are notified at once, and everyone in the console sees a banner with the date.
2. For 30 days the organization works as usual, and any owner can cancel (`DELETE /v1/org/deletion`).
3. Then every row of the organization is deleted, in every table, including its audit log. This is one database transaction: either all of it goes or none of it does.
4. The owners get a **deletion certificate** by email: the organization, when it was requested and deleted, and the rows deleted per table.

Afterwards the operator keeps only that certificate (`deleted_organizations`): the name and row counts, no tenant data.

Export your data first if you want to keep it.

## Operators

- Deletion certificates: `SELECT * FROM deleted_organizations` as the owner role.
- The grace period is `NEXUS_ORG_DELETION_GRACE_DAYS`, 30 days by default. Contracts often require 30 days.

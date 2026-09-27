# Laptop sign-in with the company account

People sign in to their Mac, Windows PC or Linux machine with their Nexus password, like JumpCloud user binding with password sync. When someone leaves, their laptop account is disabled.

## Setting it up

On a device's **Details** tab, **Local accounts → Add person**:

- **Account name:** defaults to the start of the person's email address (lower-case, up to 20 characters). System names such as root, admin or Administrator are refused.
- **Administrator on this device:** makes them a local admin (`admin` on macOS, Administrators on Windows, `sudo` or `wheel` on Linux). A local admin is effectively root, so only owners and admins can grant it. It's the same bar as running scripts (`devices:scripts`). Help desk (`devices:write`) can add standard accounts.
- **Take over an existing account:** manages an account that already exists with that name, keeping its files. Without it, the agent won't touch an existing account.

The agent creates the account right away. The account stays **locked until the person signs in to Nexus once**, which sends their password to the device. After that, the device follows their password.

## How the password gets there

Nexus stores only password hashes, so it can't produce a person's password later. Instead it passes the password on at the moments it sees it and has just checked it:

- signing in to Nexus (with a Nexus password, or a directory password from an LDAP or Active Directory connection);
- changing or resetting the password;
- accepting an invitation.

At each of those moments, for each device the person has an account on:

1. **Encrypted to that device.** Each agent generates an X25519 key when it first runs, keeps it in its state folder (root/SYSTEM only), and reports the public half in its signed check-ins. The server encrypts the password to it: an ephemeral X25519 key, HKDF-SHA256, then AES-256-GCM bound to the device, the person and the password version. Only that device can open it.
2. **Signed by your organization.** The envelope is signed with the organization's command key, which the agent pinned at enrollment. The agent refuses anything unsigned, meant for another device, expired, or older than what it has.
3. **Never stored in the clear.** Only the encrypted envelope waits in the database, and it's deleted once the device reports it has set the password (or after 30 days).
4. **Set without a command line.** The agent passes the password on stdin, never as an argument: `chpasswd` on Linux, OpenDirectory on macOS, PowerShell `Set-LocalUser` on Windows. It holds the password only in memory.

**Not re-sent needlessly:** Nexus keeps a keyed fingerprint (HMAC with the seal key) of the last password it sent, so a sign-in with the same password sends nothing. A sign-in with a different password is noticed, for example one changed in Active Directory, and is sent on.

**macOS keychain and FileVault:** after a change in Nexus, the envelope carries the old password too. That lets macOS *change* the password rather than reset it, so the login keychain and FileVault unlock keep working.

**Reinstalled agent:** a device with a new agent key drops envelopes made for the old one. The next sign-in sends the password again.

## Leavers and removals

- **Suspended, offboarded or deprovisioned:** the policy marks the account disabled. The agent disables it and removes admin rights, and no more passwords are sent.
- **Removed from the device in Nexus:** the agent disables the account. It never deletes an account or its files.
- **Changed by hand:** the agent re-checks every hour, so an account someone re-enabled or promoted by hand is put back.

## What you see

- **The device's Local accounts card:** each account's state (waiting for the device, waiting for a Nexus sign-in, active, disabled, failed with the reason), and whether it has the current password.
- **My devices:** people see their accounts and whether they're ready.
- **Audit log:** `device.local_account_bound`, `…_changed` and `…_unbound`, and from the agent `device.local_password_synced`, `device.local_account_enabled`, `…_disabled` and `…_failed`.

## Limits

- **Other sign-in routes:** people who sign in to Nexus only through an external IdP (Okta, Entra ID) never type a password into Nexus, so there's nothing to send. Their account stays locked. Passwords used over Nexus LDAP or RADIUS aren't captured either.
- **macOS FileVault on Apple silicon:** an account created by the agent has no SecureToken, so it can't unlock FileVault at boot until an existing token holder (or an MDM bootstrap token) grants one. A taken-over account keeps its token.
- **Windows password policy:** a Nexus password that doesn't meet the device's local complexity rules is refused by Windows. The account shows as failed with Windows' reason.
- **Linux passwords:** a password containing a newline can't be set with `chpasswd`.
- **Agent needs root/SYSTEM:** without it, accounts report failed.

## API

- `GET /v1/devices/{id}/accounts`
- `PUT /v1/devices/{id}/accounts/{user_id}` with `{ username?, admin, take_over }`
- `DELETE /v1/devices/{id}/accounts/{user_id}`
- `GET /v1/me/device-accounts`

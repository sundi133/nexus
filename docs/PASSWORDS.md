# Password manager

Every person gets a personal vault, and teams share vaults. Everything is **end-to-end encrypted**: items are encrypted in the browser before they're sent, so Nexus stores only ciphertext. Nobody at your company or at Votal can read them, including administrators and anyone with the database.

Open **Passwords** in the console.

## Setting up

The first time, choose a **master password** (12 characters or more). It never leaves the browser. That means:

- **Nobody can reset it.** If it's forgotten, the personal vault is lost. The person sets up again, and the owners of each shared vault share it with them again.
- Your Nexus sign-in password is separate: changing or resetting that doesn't touch the vault.

The vault locks after 10 minutes without activity, when you click **Lock**, or when the page is closed.

## Using it

- **Add** a login: name, website, username, password and notes. **Generate** makes a random 20-character password without look-alike characters.
- **Copy** the username or password, or show the password. A copied password is cleared from the clipboard after 30 seconds, if it's still there.
- **Search** covers names, websites and usernames.
- Revealing or copying is recorded in the audit log as `vault.item_used` with the item's ID. The secret is never recorded.

## Shared vaults

**New shared vault** makes one you own. **Share** it with anyone who has set up the password manager:

| Role | Can |
|---|---|
| Viewer | Read and copy |
| Editor | Also add, change and delete items |
| Owner | Also share, change roles, remove people and delete the vault |

A vault always keeps at least one owner. Anyone can leave a vault. Personal vaults can't be shared: move items into a shared vault instead.

When you share, the page shows the other person's **key fingerprint**. They see theirs under **Change master password**. For sensitive vaults, compare the two over another channel (a call, in person). This rules out a server that swapped in a different key.

## Offboarding

Offboarding someone removes them from every vault straight away, and their personal vault is deleted. Shared vaults nobody is left in are deleted too. A shared vault that loses its last owner gets a new one: the longest-standing editor, or failing that the longest-standing member. The offboarding summary lists these as `password_vaults_removed` and `password_vault_owners_promoted`.

Removing someone stops the server handing them ciphertext. But anything they already saw or copied is theirs. **Rotate the passwords** in a vault someone leaves, as you would with any shared credential.

## How the encryption works

| Piece | How |
|---|---|
| Master key | PBKDF2-SHA256, 600,000 rounds, random 16-byte salt → AES-256-GCM key |
| Your key pair | RSA-OAEP 3072-bit (SHA-256). The private key is stored encrypted with the master key; the public key is stored plainly, so others can share with you |
| Vault key | Random AES-256-GCM key per vault. It encrypts the vault's name and items (a fresh 12-byte IV each time) |
| Sharing | The vault key is wrapped with RSA-OAEP to each member's public key, in the sharer's browser |
| Changing the master password | Re-encrypts only your private key. Vault keys and items stay as they are |

It all uses the browser's WebCrypto API (`apps/web/src/lib/vault-crypto.ts`). The server:

- checks membership and role on every call;
- won't let a person's public key change once it's set, since shared vaults are wrapped to it;
- shows administrators counts only (`GET /v1/vault/overview`).

## Limits

- **No browser autofill** yet: copy from the Passwords page. The Nexus browser extension may fill logins later.
- **No mobile access** yet.
- **No import** from other password managers, and no TOTP codes.
- **No recovery** for a forgotten master password (by design). An admin recovery key, escrowed to the organization, is a possible later option.
- **Trusting the page:** the page is served by Nexus. Someone who controls the server could serve a changed page to capture a master password. Only a separately installed client (an extension or an app) removes that trust.

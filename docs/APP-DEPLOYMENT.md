# App deployment

**Devices → App deployment** installs and removes apps on devices, like JumpCloud Software Management.

| Type | Platform | How the agent finds it | Where it comes from |
|---|---|---|---|
| winget | Windows | winget package ID (`Zoom.Zoom`) | the winget sources, installed machine-wide |
| MSI | Windows | ProductCode (`{…}`) in the Uninstall registry | your https URL, checked against its SHA-256 |
| .pkg | macOS | the package receipt ID (`pkgutil --pkgs`) | your https URL, checked against its SHA-256 |
| apt | Linux (Debian, Ubuntu) | package name | the device's apt sources |
| dnf | Linux (Fedora, RHEL) | package name | the device's dnf repositories |

## How it works

- **Assignments:** each app is assigned to every device on its platform, or to a group's devices (those whose primary user is in the group), to **install** or to **remove**. When both apply to a device, install wins.
- **Desired state:** each device gets its apps inside its device policy, signed with your organization's key. This is the same signed policy that carries block rules and device settings. The agent pinned that key at enrollment and refuses any policy that is unsigned, altered, meant for another device, or older than the one it has.
- **Reconciling:** when a new policy arrives, the agent installs what's missing and removes what shouldn't be there, in the background as root or SYSTEM. It checks again every hour, so an app someone uninstalled comes back. After each install it checks that the app is really there. An installer that exits cleanly without installing anything is reported as failed.
- **Failures:** a failed app is retried after 6 hours, or at once if you change it. Each install is limited to 30 minutes.
- **Reporting:** every app on every device reports installed, not installed, failed (with the reason) or unsupported. The console shows counts per app and the state on each device. Installs, removals and new failures are in the audit log (`device.software_installed`, `device.software_removed`, `device.software_failed`).

## Safety

- **Verified downloads:** MSI and .pkg downloads must be https (including redirects) and match the SHA-256 you give. The agent refuses anything else before running it. Downloads are capped at 4 GB and deleted after the install.
- **No argument smuggling:** the server and the agent both check references against a strict pattern per type, so a reference can't pass an option to the package manager.
- **Who can change it:** installers run as root or SYSTEM, so changing the catalog or assignments needs `devices:software` (owners and admins, never API keys) and a recent MFA. Every change is audited. Anyone with `devices:read` can see the catalog and states.

## Limits

- **.pkg can't be removed:** macOS packages have no uninstaller. Remove those apps with a script.
- **winget needs App Installer:** it ships with Windows 10 1809+ and Windows 11. Without it, winget apps report "winget (App Installer) isn't on this device".
- **Agent without admin rights:** an agent that isn't running as root or SYSTEM reports every app as unsupported.
- **No Homebrew:** it runs as a person, not as root. Use a .pkg instead.

## API

- `GET` and `POST /v1/software-packages`; `PUT` and `DELETE /v1/software-packages/{id}`.
- `POST /v1/software-packages/{id}/assignments` with `{ action: install | remove, group_id | null }`, and `DELETE …/assignments/{assignment_id}`.
- `GET /v1/software-packages/{id}/devices`: the state on each device the app is assigned to.

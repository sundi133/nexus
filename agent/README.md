# Nexus agent

Reports device posture to Votal Nexus. Written in Go, one static binary per platform (ADR-013). The only dependency is `golang.org/x/sys`, for the Windows service.

```bash
go build -o nexus-agent ./cmd/nexus-agent                    # this machine
GOOS=windows GOARCH=amd64 go build ./cmd/nexus-agent          # cross-compile
go test ./...
```

```bash
sudo nexus-agent install --server https://api.nexus.example --token nxe_…  # copy to the system location, enroll, run at boot
sudo nexus-agent uninstall [--purge]                                       # --purge also deletes the device key
sudo nexus-agent enroll --server https://api.nexus.example --token nxe_…   # enroll only, from Devices → Add devices, or My devices
sudo nexus-agent run            # check in every ~60 s (run under launchd / systemd / a Windows service)
nexus-agent run --once          # one check-in
nexus-agent posture             # print what would be reported, without sending anything
nexus-agent status
```

Use `--state-dir` to keep state somewhere other than the system default (`/Library/Application Support/Nexus`, `/var/lib/nexus-agent`, `%ProgramData%\Nexus`).

## Security model (ADR-015)
- **Device key:** on enrollment the agent generates an ECDSA P-256 key. The private key stays on the device (file mode `0600`) and the public key is registered, with proof of possession.
- **Signed requests:** every request carries `Authorization: NexusDevice <jwt>`, an ES256 token signed by that key. It's bound to the method, path and SHA-256 of the body, lives at most 2 minutes, and has a single-use `jti`.
- **Facts only:** the agent reports raw facts. The server decides compliance, and anything the agent can't read is reported as `unknown`, never `on`.
- **HTTPS only:** plain HTTP is refused except to localhost.
- **Browser device checks:** `run` also listens on `127.0.0.1:47823` (loopback only). When an app's access policy needs to know which device a browser is on, the Nexus console asks the agent to sign a one-time nonce. The agent answers only the console origin the server gave it (`web_origin`), refuses other Host headers (DNS rebinding), and includes the origin in the signed statement.
- **Removal:** a removed device gets `device_not_enrolled`, and the agent then clears its local enrollment.

## What it reads

| Check | macOS | Windows | Linux |
|---|---|---|---|
| Disk encryption | `fdesetup status` | BitLocker via `Get-BitLockerVolume` (admin) | LUKS in the root device's ancestry (`lsblk`) |
| Firewall | `socketfilterfw --getglobalstate` | `netsh advfirewall` (all profiles) | ufw / firewalld |
| Screen lock | `sysadminctl -screenLock status` | Machine inactivity limit policy | unknown (per-user desktop setting) |
| System integrity | `csrutil status` (SIP) | `Confirm-SecureBootUEFI` | `mokutil --sb-state` |
| OS, model, serial | `sw_vers`, `sysctl`, `ioreg` | registry, CIM | `/etc/os-release`, DMI |
| Software, listening ports, USB, browser extensions, startup items | osquery, bundled with the installers ([docs/OSQUERY.md](../docs/OSQUERY.md)) | same | same |
| AI tools and MCP servers | Known AI clients' config files in each account's home, and installed AI apps, CLIs and extensions. Names and targets only, never secret values: see [AI on devices](../docs/AI-ON-DEVICES.md) | same | same |

## Installing (DEV-01)
`install` runs the agent at boot and restarts it whenever it exits:
- **macOS:** LaunchDaemon `ai.votal.nexus-agent`, binary in `/Library/Application Support/Nexus/bin`, logs in `/Library/Logs/Nexus/agent.log`.
- **Linux:** systemd unit `nexus-agent.service`, binary in `/opt/nexus/bin`.
- **Windows:** service `NexusAgent`, set to restart on exit.

The macOS package (`nexus-agent-<version>.pkg`) holds a universal binary. For MDM rollout, deploy `/Library/Application Support/Nexus/enroll.conf` (`server=…` and `token=…` lines) before the package: the postinstall script enrolls and then deletes the file. Installing over an enrolled Mac upgrades it in place.

The Windows packages (`nexus-agent-<version>-x64.msi` and `-arm64.msi`) are for Intune, Group Policy or any software-deployment tool:

```
msiexec /i nexus-agent-1.2.3-x64.msi /qn SERVER=https://api.nexus.example.com TOKEN=nxe_…
```

- **What it installs:** the binary in `C:\Program Files\Nexus` and the `NexusAgent` service (automatic start, restarts on exit).
- **State folder:** `C:\ProgramData\Nexus`, limited to SYSTEM and Administrators because it holds the device key.
- **Enrollment:** with `TOKEN`, the installer leaves `enroll.conf` there. The service enrolls from it (retrying until the server is reachable) and deletes it. `TOKEN` is hidden from installer logs. Without `TOKEN`, the service waits until someone runs `nexus-agent install --server … --token …`.
- **Upgrades:** installing a newer `.msi` upgrades in place.
- **Uninstalling:** removes the program and the service, but keeps the device key, so a reinstall resumes the same device.

The Linux packages (`nexus-agent_<version>_amd64.deb`, `nexus-agent-<version>-1.x86_64.rpm`, and arm64) install the binary in `/opt/nexus/bin` (linked from `/usr/bin`) and a systemd unit, and start the agent.
- **Enrolling with configuration management:** drop `/var/lib/nexus-agent/enroll.conf` (`server=…` and `token=…`); the service enrolls itself.
- **Enrolling by hand:** `sudo nexus-agent install --server … --token …`.
- **Removing:** removing the package keeps the device key, and `apt purge` deletes it. Upgrades restart the agent on the new version.
- **Testing:** CI installs the `.deb` on a real systemd host and the `.rpm` in Fedora.

Everything is declarative Windows Installer (no custom actions). CI installs, upgrades and uninstalls it on Windows and checks the service, ACLs and logs.

## Updates (DEV-07, ADR-017)
The server offers an update in the check-in response when this device's rollout stage is due. Agents move canary → 10% → everyone. The agent then:
1. **Verifies the offer** against the Ed25519 release keys compiled into it (`-X main.releaseKeys=…`), so a compromised server can't push code. It refuses downgrades, and a build without keys installs nothing.
2. **Downloads** exactly the signed size and checks the SHA-256.
3. **Self-tests** the new binary (`nexus-agent selftest`) before touching the installed one.
4. **Swaps** atomically, keeping `nexus-agent.previous`, then restarts in place (Windows: exits, and the service restarts).
5. **Rolls back** if the new version restarts more than 3 times without checking in, or can't check in within 10 minutes. It restores `.previous` and keeps the bad binary as `.failed`.

Every outcome (`installed`, `failed`, `rolled_back`) is reported with the next check-in. Any failure halts the rollout for the whole organization and alerts admins.

## Releasing
```bash
pnpm agent:release 0.2.0 "What changed"    # all platforms → agent/dist/releases/0.2.0 + agent/dist/installers/*.pkg
```
Set `NEXUS_RELEASE_KEY` to the release key (without it, a dev key is generated in `agent/dist`). Point the API at the output with `NEXUS_AGENT_RELEASES_DIR` and `NEXUS_AGENT_RELEASE_KEYS`; in dev both default to `agent/dist`. Releases are immutable, so re-signing a version is refused.

Windows installers are built on Windows, with the WiX Toolset v5 (`dotnet tool install --global wix --version 5.0.2`), from a release directory: `agent/packaging/windows/build-msi.ps1 -Version 0.2.0 -ReleaseDir agent/dist/releases/0.2.0 -OutDir agent/dist/installers`.

**Signed releases** come from the *Agent release* GitHub workflow. It:
- codesigns and notarizes for macOS (Developer ID);
- Authenticode-signs for Windows (Azure Trusted Signing, DigiCert KeyLocker or a `.pfx`, via `scripts/sign-windows.sh`), before the Ed25519 release signature, so self-updates and installers carry identical bytes;
- checks every signature with `scripts/verify-signatures.sh`;
- installs the signed `.msi` on a clean Windows machine;
- drafts a GitHub release.

[docs/SIGNING.md](../docs/SIGNING.md) covers getting the certificates, the secrets, and deploying through Jamf and Intune.

## Not yet
- **Hardware-backed key:** Secure Enclave on macOS, TPM on Windows.
- **Remote commands:** these need the long-lived stream.

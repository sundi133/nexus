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

## Installing (DEV-01)
`install` runs the agent at boot and restarts it whenever it exits:
- **macOS:** LaunchDaemon `ai.votal.nexus-agent`, binary in `/Library/Application Support/Nexus/bin`, logs in `/Library/Logs/Nexus/agent.log`.
- **Linux:** systemd unit `nexus-agent.service`, binary in `/opt/nexus/bin`.
- **Windows:** service `NexusAgent`, set to restart on exit.

The macOS package (`nexus-agent-<version>.pkg`) holds a universal binary. For MDM rollout, deploy `/Library/Application Support/Nexus/enroll.conf` (`server=…` and `token=…` lines) before the package: the postinstall script enrolls and then deletes the file. Installing over an enrolled Mac upgrades it in place.

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
Set `NEXUS_RELEASE_KEY` to the release key (without it, a dev key is generated in `agent/dist`). For signed and notarized macOS builds, set `NEXUS_CODESIGN_IDENTITY`, `NEXUS_INSTALLER_IDENTITY` and `NEXUS_NOTARY_PROFILE`. Point the API at the output with `NEXUS_AGENT_RELEASES_DIR` and `NEXUS_AGENT_RELEASE_KEYS`; in dev both default to `agent/dist`. Releases are immutable, so re-signing a version is refused.

## Not yet
- **Windows `.msi` and Linux `.deb`/`.rpm` packages:** these need Windows and Linux build hosts. The binaries, service installation and self-update already work on both.
- **Real Developer ID signing:** needs the certificates. The hooks are in place.
- **Hardware-backed key:** Secure Enclave on macOS, TPM on Windows.
- **osquery-based inventory** (ADR-006).
- **Remote commands:** these need the long-lived stream.

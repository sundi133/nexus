# Nexus agent

Reports device posture to Votal Nexus. Written in Go with **no third-party dependencies**, one static binary per platform (ADR-013).

```bash
go build -o nexus-agent ./cmd/nexus-agent                    # this machine
GOOS=windows GOARCH=amd64 go build ./cmd/nexus-agent          # cross-compile
go test ./...
```

```bash
sudo nexus-agent enroll --server https://api.nexus.example --token nxe_…   # from Devices → Add devices, or My devices
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
- **Removal:** a removed device gets `device_not_enrolled`, and the agent then clears its local enrollment.

## What it reads

| Check | macOS | Windows | Linux |
|---|---|---|---|
| Disk encryption | `fdesetup status` | BitLocker via `Get-BitLockerVolume` (admin) | LUKS in the root device's ancestry (`lsblk`) |
| Firewall | `socketfilterfw --getglobalstate` | `netsh advfirewall` (all profiles) | ufw / firewalld |
| Screen lock | `sysadminctl -screenLock status` | Machine inactivity limit policy | unknown (per-user desktop setting) |
| System integrity | `csrutil status` (SIP) | `Confirm-SecureBootUEFI` | `mokutil --sb-state` |
| OS, model, serial | `sw_vers`, `sysctl`, `ioreg` | registry, CIM | `/etc/os-release`, DMI |

## Not yet
- **Installers and services:** signed, notarized packages (`.pkg`, `.msi`, `.deb`/`.rpm`) and service installation (launchd, systemd, Windows service).
- **Hardware-backed key:** Secure Enclave on macOS, TPM on Windows.
- **osquery-based inventory** (ADR-006).
- **Remote commands:** these need the long-lived stream.

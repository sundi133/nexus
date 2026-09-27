# Device settings: fixing, not just reporting

Device policies check each device's firewall, screen lock and disk encryption, and grade its compliance. With **Fix it on devices** turned on for a policy, the Nexus agent also makes the device match it. It re-applies the setting every hour, so one someone turns off comes back.

It's **off by default**: turning settings on changes people's devices. Only BitLocker recovery-key escrow is on by default, and it doesn't change the device.

## What each OS does

| Setting | Windows | macOS | Linux |
|---|---|---|---|
| **Firewall** | Windows Firewall on for all profiles | Application firewall on | `ufw` (SSH is allowed first, so a remote machine is never locked out) or `firewalld` |
| **Screen lock** | Machine inactivity limit, the Group Policy setting; applies after a restart | ✗ Needs a configuration profile from your MDM | GNOME: idle delay and lock, locked in the system dconf database so people can't lengthen it; applies at next sign-in. Servers without a desktop: not applicable |
| **Disk encryption** | BitLocker on the system drive, only with a ready TPM. A recovery password is added first, then the TPM protector, then encryption (used space only, in the background) | ✗ FileVault is turned on by the user or by your MDM's FileVault payload, which also escrows its key | ✗ LUKS is chosen at install time: re-provision the device |
| **Recovery-key escrow** | BitLocker recovery passwords, sealed on the server. If BitLocker is on with only a TPM, a recovery password is added so there's something to recover with | Use your MDM's FileVault escrow | — |

The agent must run as root / SYSTEM, which the installers do.

On each device's **Compliance** tab, *Settings Nexus enforces* shows each setting's outcome:
- **In place:** the device already matched.
- **Fixed:** the agent changed it; some changes apply after a restart.
- **Couldn't fix:** the agent tried and failed; the reason is shown.
- **Not on this OS:** the OS needs MDM or the user for it.

Changes and failures go into the audit log (`device.setting_applied`, `device.setting_failed`) once each, not every hour.

## Recovery keys

- **Stored:** keys are sealed with the same AES-256-GCM seal keys as every other secret, and rotated with `reseal`. They never appear in logs or the audit log.
- **Revealed:** only on *Reveal recovery key* on the device, which needs the `devices:recovery_keys` permission (owners, admins and help desk, and scoped help desk for their groups' devices), a recent MFA, and never an API key. Every reveal is audited (`device.recovery_key_viewed`).
- **Rotated:** a key the device no longer reports is kept, marked retired, for recovering older backups.

## How it's delivered

Settings travel in the same signed policy as block rules ([BLOCK-RULES.md](BLOCK-RULES.md)), signed with the organization's key that the agent pinned at enrollment. The agent refuses a policy that's unsigned, meant for another device, or older than the one it has. So neither the network nor a replayed response can change a device's settings.

## How to test it

1. In **Device policies**, turn on **Fix it on devices** for the firewall, and for the screen lock (for example 5 minutes).
2. **Windows test VM** (admin PowerShell):
   ```powershell
   netsh advfirewall set allprofiles state off
   Restart-Service NexusAgent       # or wait for the hourly pass
   netsh advfirewall show allprofiles state   # ON again
   reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v InactivityTimeoutSecs   # 300
   ```
   With BitLocker on, the device shows *BitLocker recovery key escrowed*. *Reveal recovery key* shows the same 48-digit password as `manage-bde -protectors -get C: -Type RecoveryPassword`.
3. **Ubuntu test VM:**
   ```bash
   sudo ufw disable && sudo systemctl restart nexus-agent
   sudo ufw status verbose   # active, with OpenSSH allowed
   ```
4. **Mac:** `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off`, restart the agent (`sudo launchctl kickstart -k system/ai.votal.nexus-agent`), and the firewall is back on. The screen lock shows *Not on this OS* with what to do instead.

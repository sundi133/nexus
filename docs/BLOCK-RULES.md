# Block rules: stopping apps and domains on devices

**Devices → Block rules** stops apps and domains on the devices running the Nexus agent. It's meant for unapproved AI tools, shadow-AI web services, and MCP servers that bypass the gateway.

| Rule | What the agent does | How strong it is |
|---|---|---|
| **App**, matched by program name, path or folder, or SHA-256 | Checks running programs about every 2 seconds and ends matching ones at once (SIGKILL / TerminateProcess) | Stops the app within about 2 seconds of launch. It doesn't prevent the launch. Pre-launch blocking on macOS needs Nexus's own Endpoint Security entitlement (planned) |
| **Domain** | Adds the domain to a Nexus-managed section of the hosts file (`0.0.0.0` and `::`), then flushes the DNS cache | Ordinary apps and browsers can't reach it. A local admin can edit the hosts file back, and DNS-over-HTTPS in some browsers or a raw IP address get around it |

## How it's kept safe

- **Monitor first.** New app rules start in *monitor* mode. Devices report what the rule *would* stop, once per launch, and you switch to **Start blocking** when the matches look right. The confirmation shows how often the rule matched in the last 7 days. Domain rules block straight away.
- **Signed by your organization.**
  - Each device receives only the rules that apply to it (by platform and group), as a policy signed with the organization's key that the agent pinned at enrollment.
  - The agent refuses a policy that's unsigned, meant for another device, or older than the one it has; a replayed response is older.
  - It keeps the last policy on disk, so rules apply from boot and while the device is offline.
- **Things it never blocks.** The server refuses these rules, and the agent refuses them again:
  - the operating system: `launchd`, `WindowServer`, `loginwindow`, `csrss.exe`, `lsass.exe`, `svchost.exe`, `explorer.exe`, `systemd`, `sshd` and others;
  - anything under `/System/`, `C:\Windows\System32\` or Nexus's own folders;
  - the agent itself and osquery;
  - a whole disk (`/` or `C:\`);
  - the Nexus server's own domain.
- **Who can change rules.** Owners and Admins, with the `devices:enforce` permission. It isn't available to API keys. Changes need a recent MFA and are audited (`enforcement.rule_created`, `_updated`, `_deleted`).
- **Everything is reported.**
  - Each stop, would-stop or failure (for example, the hosts file couldn't be written) reaches the console on the next check-in and goes into the audit log (`device.app_terminated`, `device.app_would_terminate`, `device.enforcement_failed`).
  - The built-in alert *Blocked app keeps coming back* fires when one device stops the same app 5 times in an hour.

## Writing rules

| To stop | Use |
|---|---|
| A macOS app with all its helper processes | **Path or folder**: `/Applications/Example.app/` (ending with `/`) |
| A Windows program | **Path or folder**: `C:\Program Files\Example\`, or **program name** `example.exe` |
| A CLI wherever it's installed | **Program name**, e.g. `ollama`. It matches `ollama` and `ollama.exe` |
| One exact build, even renamed | **SHA-256** of the executable |
| A web service or remote MCP server | **Domain**: `chat.example.com`. It must be the exact name; `www.` and other subdomains need their own rules |

Paths are case-insensitive on macOS and Windows and case-sensitive on Linux. **Devices → AI on devices** shows the AI apps and MCP server hosts people actually use: a good place to find what to write rules for.

## Where to see it

- **Block rules:**
  - each rule, its mode, and how often it matched in the last 7 days;
  - every event, by device.
- **A device → Actions tab:**
  - whether the device has applied the current rules (*Up to date* or *Waiting for the device*) and what it reports, e.g. `2 app rules (1 blocking), 1 domains blocked` or why something failed;
  - that device's events.

## How to test it

### 1. On a Linux machine or container (as root)
```bash
# In the console: Block rules → Add rule
#   App, Program name "yes", then Start blocking
#   Domain "chat.example.com"
sudo nexus-agent install --server https://api.nexus.example.com --token nxe_…
yes > /dev/null &        # ended within ~2 seconds ("Killed")
getent hosts chat.example.com   # → 0.0.0.0 / ::
sed -n '/BEGIN Votal Nexus/,/END Votal Nexus/p' /etc/hosts
```
The events show up under **Block rules → What devices stopped** after the next check-in (up to a minute).

### 2. On a test Mac
1. Add an app rule for a harmless app, e.g. **Path or folder** `/System/Applications/Chess.app/`. This is refused: system apps are protected. Use an app you installed, like `/Applications/Slack.app/`, and keep it in monitor mode.
2. Open that app. Within a minute the rule shows **Would stop ×1**, and the app keeps running.
3. Click **Start blocking**. Open the app again: it closes within about 2 seconds, and **Stopped** appears.
4. Add a domain rule and try it in a browser. On macOS the agent flushes the DNS cache when rules change.

### 3. On Windows (admin PowerShell)
```powershell
# Rule: Program name "notepad.exe", blocking
notepad.exe            # closes within ~2 seconds
Get-Content $env:SystemRoot\System32\drivers\etc\hosts | Select-String "Votal Nexus" -Context 0,4
```

### 4. What must not happen
- A rule for `launchd`, `svchost.exe`, `/` or your Nexus domain is refused when you save it.
- Replacing the policy in transit is refused by the agent: its log shows `block rules refused`.
- Turning a rule off, or removing it, undoes it on the next check-in: the program runs again, and the hosts section is removed.

## Limits

- **App rules:**
  - an app runs for up to ~2 seconds before it's ended;
  - a local admin can stop the agent;
  - without root, the agent sees and ends only its own user's programs.
- **Domain rules:**
  - exact names only;
  - bypassable by a local admin, DNS-over-HTTPS or IP addresses.

  For stronger network control, use your network or DNS filter; the domains here are the ones to feed it.
- No end-user notification when an app is ended yet; the person sees the app close.

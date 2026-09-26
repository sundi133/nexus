# Real-time process events and detections

With **Settings → Organization → Collect real-time process events** on, every device reports each program it starts within about 15 seconds. It reports the path, the command line (secrets removed), the user, and the chain of programs that started it. Nexus looks for AI tools doing risky things.

It's **off by default**. It collects command lines, so tell employees before you turn it on.

## Where the events come from

The agent runs its own copy of the **osqueryd** bundled with the installers. It has its own configuration, database, pidfile and logs in the agent's state folder, extensions are off, and osquery's watchdog caps its CPU and memory. It uses each OS's own event source:

| OS | Source | osquery table |
|---|---|---|
| macOS | Endpoint Security (osquery's own Apple entitlement) | `es_process_events` |
| Windows | ETW | `process_etw_events` |
| Linux | eBPF | `bpf_process_events` |

It never touches an osquery you run yourself. Each device reports whether collection is running, and if not, why:

| Status | What to do |
|---|---|
| `running: osquery Endpoint Security` / `ETW` / `eBPF` | Nothing |
| macOS refused Endpoint Security: grant Full Disk Access… | Deploy a PPPC profile giving **Full Disk Access** to `/Library/Application Support/Nexus/osquery/osquery.app` (bundle `io.osquery.agent`, team `3522FA9PXF`) and to the agent (`/Library/Application Support/Nexus/bin/nexus-agent`) |
| eBPF needs the kernel's tracing filesystem… | Mount debugfs at `/sys/kernel/debug` (standard on most distributions; missing in some containers); kernel 4.18 or later |
| the agent must run as root / SYSTEM | Run the agent as a service (the installers do) |
| osquery isn't installed | Install with a Nexus installer (they include osquery) |

## What's detected

**Parent chain.** Each event carries its parent chain. The agent traces it from the launches it has seen, so it still works after short-lived shells exit, and even when a program execs another in place (`claude -c "bash …"`). On macOS it also records the *responsible* app.

| Finding | Severity | What it is |
|---|---|---|
| **AI ran a network tool** | High | `curl`, `wget`, `scp`, `ssh`, `nc`, `rsync`, `certutil.exe`, `bitsadmin.exe`… started (directly or through shells) by an AI tool: Cursor, Claude (desktop or CLI), Codex, Gemini CLI, Windsurf, VS Code, ChatGPT and others. It may be moving data off the device |
| **AI started a shell** | Info | An AI tool ran a shell. Coding agents do this all the time; it's recorded for investigation, not alerted |
| **Ran from temp/Downloads** | Low | A program started from a temporary or downloads folder |

- **Audit and alert:** high findings are audited (`device.detection`, once an hour per device and program) and raise the built-in alert **AI tool ran a network tool**. That reaches your on-call and SIEM like any other alert.
- **In the console:**
  - **Insights → Detections** lists findings across devices;
  - **a device → Processes** shows its full timeline, with a *Findings* filter and search.

## Privacy and retention

- **Redacted command lines.** The agent removes secrets before sending, and the server removes them again:
  - bearer and basic credentials;
  - tokens (GitHub, Slack, OpenAI, AWS, Google, Notion, Linear…) and JWTs;
  - `password=…`, `--token …`-style values;
  - credentials in URLs.

  Command lines are capped at 2,000 characters.
- **Retention:** events are kept **7 days**, then deleted.
- **Permissions:** viewing needs `devices:read`. Scoped admins see only their groups' devices on each device's page, and the fleet-wide Detections page needs org-wide access.
- **Turning it off:** the next check-in stops osqueryd on every device, and uploads are refused from then on.

## How to test it

1. Turn on **Collect real-time process events** in **Settings → Organization**.
2. On a Linux test machine with the agent installed:
   ```bash
   cp /bin/bash /usr/local/bin/claude      # stands in for an AI coding CLI
   claude -c 'bash -c "curl -s https://example.com -o /dev/null || true"'
   ```
   Within about 20 seconds, **Detections** shows *curl, started by bash ← claude: AI ran a network tool*, and **Alerts** shows *AI tool ran a network tool*.
3. On a Mac with the agent and a Full Disk Access profile: in Cursor's terminal or agent, run `curl https://example.com`. The finding says *Cursor ran curl*.
4. Check the device's **Processes** tab: its status should be `running: osquery …`. A command with `--token abc…` shows `--token <redacted>`.

## Limits

- **Observation only.** To stop an app, use **Block rules**.
- **Reporting delay:** events arrive within about 15 seconds; osquery runs the query every 10 seconds, and the agent uploads every 5.
- **AI tool detection works by path and name.** A renamed AI tool isn't recognized.
- **Offline buffer:** up to 10,000 events. Beyond that the device reports how many it dropped.

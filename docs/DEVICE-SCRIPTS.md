# Scripts on devices

**Devices → Scripts** runs scripts on devices, like JumpCloud Commands: check disk space, rotate a local admin password, remove an app, collect a log.

- **The library** holds scripts you run often: bash, zsh or sh for macOS and Linux, PowerShell for Windows.
- **A run** sends a script to every device (or a group's devices, or chosen devices) whose OS can run it. Devices pick it up at their next check-in (about a minute), or within a day if they're offline.
- **Results:** each device returns its exit code, how long the script took, and its output (stdout and stderr, up to 64 KB).

## Safety

- **Signed:** the script travels inside a command signed with your organization's key, which the agent pinned at enrollment. The agent refuses anything unsigned, altered, meant for another device, expired or replayed.
- **Runs as root or SYSTEM:** anything the device can do. So only owners and admins (`devices:scripts`) can run scripts, never an API key, and only with a recent MFA.
- **Audited:** every run is in the audit log (`device.script_run`) with its reason, targets and the script's SHA-256. Library changes are audited too. Each run keeps its own copy of the script, so later edits don't rewrite history.
- **Limits:** a time limit per run (5 minutes by default, 30 at most). When it runs out, the whole process tree is stopped. Output is capped at 64 KB.

## API

`POST /v1/script-runs` with `{ script_id | script: { name, shell, body }, reason, target: { all | group_id | device_ids }, timeout_seconds }`, then `GET /v1/script-runs/{id}` for each device's result.

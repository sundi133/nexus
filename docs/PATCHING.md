# OS patching

**Devices → OS updates** shows the operating-system updates pending on each device and installs them, like JumpCloud's patch policies.

- **Checking:** the agent checks every 6 hours, in the background, with the OS's own tool: `softwareupdate` on macOS, the Windows Update API on Windows, and `apt` or `dnf` on Linux. It reports what's pending with its inventory. It re-checks after an install.
- **Security or not:** on Linux, packages from a `-security` suite (apt) or named by a security advisory (dnf). On Windows, updates in the Security or Critical categories. Apple doesn't say which macOS updates fix security issues, so every macOS update counts.
- **Major upgrades are never installed by patching.** A new major macOS (such as macOS 27 on 14) or a Windows feature update is shown as "major upgrade" but isn't counted as pending, and installs skip it. Moving to a new major version is a deliberate choice. On macOS the agent installs updates by label, never with `--all` or `--recommended`, because those would start the upgrade too.
- **Since when:** Nexus records when a device went from nothing pending to something pending. The clock stops only when nothing is left. A failed check (for example an unreachable mirror) doesn't reset it.

## Installing

- **Now:** **Install updates** targets every device, a group's devices, or one device. You choose security or all updates, and whether to restart when the OS needs it. Only devices with something pending get the install. Devices already installing are skipped.
- **Patch policy:** installs security (or all) updates once they've been pending longer than the deadline (0–90 days). It runs only on devices that are online, and only inside a maintenance window: local hours in a time zone you choose, which can wrap past midnight. A failed install is retried after 12 hours, not in a loop.
- **Restarts:** with **When the update needs it**, the agent restarts through the same restart action admins use, which warns the signed-in person first. With **Never**, people restart when they're ready.

Installs are `updates` commands signed with your organization's key. The agent refuses anything unsigned, altered, meant for another device, expired or replayed. An install is limited to an hour, and the device doesn't check in while it runs. Changing the policy and installing need `devices:updates` (owners and admins) and a recent MFA. Both are audited: `device.patch_policy_changed`, and `device.updates_install` (with `automatic: true` when the policy did it). Each device's result is recorded as `device.action_finished`.

## Compliance

The **Security updates installed** device policy (`os_updates`) fails a device whose security updates have waited longer than you allow (14 days by default). It starts off and in audit mode. Use it with conditional access to keep unpatched devices away from sensitive apps.

## Limits

- **macOS:** on Apple silicon, installing macOS itself needs an MDM bootstrap token or the person's approval. Without them, `softwareupdate` refuses and the install is reported as failed. App updates and Rapid Security Responses install normally. Nexus's own MDM (see the roadmap) will send `ScheduleOSUpdate`.
- **Linux:** needs apt or dnf. Other package managers report "no apt or dnf on this device".
- **Timing:** the check runs every 6 hours, so a new update appears in Nexus within about 6 hours plus the 15-minute inventory interval.

## API

- `GET /v1/device-updates`: the fleet, with a summary and the policy.
- `GET /v1/devices/{id}/updates`: one device's pending updates and its installs.
- `POST /v1/device-updates/install` with `{ target: { all | group_id | device_ids }, scope, restart, reason }`.
- `GET` and `PUT /v1/patch-policy` with `{ enabled, scope, deadline_days, restart, window_start, window_end, timezone }`.

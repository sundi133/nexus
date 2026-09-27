# Device health alerts

Nexus tells you when a device needs attention, through the same alert rules as everything else (**Insights → Alerts**): notifications, on-call, your SIEM and webhooks.

| Alert rule | Fires when | Default |
|---|---|---|
| **Device offline** | A device hasn't checked in for longer than your limit | 3 days |
| **Disk nearly full** | The system disk has less free space than your limit | 10% |
| **Device fell out of compliance** | A device stops meeting your device policies, after any grace period | on |

Set both limits under **Settings → Organization**. Each rule can be turned off, or its severity changed, under **Alerts → Rules**.

## How it works

- **Offline:** every 5 minutes, Nexus looks for active devices whose last check-in is older than the limit. Each episode is recorded once (`device.went_offline`), and again when the device checks in (`device.back_online`). Laptops go quiet over weekends and holidays, so set the limit to suit your fleet.
- **Disk:** the agent reports its system volume's size and free space with each inventory. On macOS that's the data volume, where people's files are; on Windows it's the system drive. When free space drops under the limit, Nexus records `device.disk_low`. It records `device.disk_ok` once free space is 2 points above the limit again, so a disk hovering at the line doesn't flap.
- **Compliance:** `device.compliance_changed` has always been recorded; the new rule alerts on changes to non-compliant.

The device page shows its disk space under **Inventory → Hardware and users**.

## Limits

- **Disk space needs the updated agent.** Older agents don't report it.
- **Only the system volume:** external and secondary disks aren't watched.
- **No CPU or memory load alerts:** Nexus doesn't sample performance.

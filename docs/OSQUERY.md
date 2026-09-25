# osquery: inventory and live queries

The Nexus agent uses [osquery](https://osquery.io) for two things:
- **an inventory pack** it collects every 6 hours;
- **live queries**: an admin asks every device a question in SQL and gets answers within about a minute.

osquery is optional. Without it, devices report posture and AI tools as before, and the console explains what's missing.

## Installing osquery

The agent uses osquery's official build and doesn't bundle it (yet). Deploy osquery next to the agent with your MDM or package manager:

| Platform | Package | Where the agent finds it |
|---|---|---|
| macOS | `osquery-<version>.pkg` from osquery.io (signed by osquery's Apple Developer ID) | `/usr/local/bin/osqueryi`, `/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd` |
| Windows | `osquery-<version>.msi` | `C:\Program Files\osquery\osqueryi.exe` |
| Linux | `.deb` / `.rpm` from osquery.io, or its apt/yum repository | `/usr/bin/osqueryi`, `/opt/osquery/bin/osqueryi` |

`NEXUS_OSQUERY_PATH` points the agent at any other location.

The agent runs osquery's shell **one query at a time**, with extensions and events off and a throwaway database each time. It never touches the configuration, database or logs of an osqueryd that's already running, for example one managed by another tool. You only need the package installed; the osqueryd service can stay off.

## The inventory pack

| Table | What | Rows kept |
|---|---|---|
| Software | macOS: apps in `/Applications` and `~/Applications`, plus Homebrew. Windows: installed programs, plus Chocolatey. Linux: deb and rpm packages | 5,000 |
| Listening ports | Process, port, protocol, address | 500 |
| USB devices | Vendor, model, IDs | 300 |
| Browser extensions | Chrome-family and Firefox, per user and profile | 2,000 |
| Startup items | What runs at boot or sign-in | 1,000 |

The agent sends it when it changes, and at least daily; the **Refresh** device action collects it at once. The pack shows on each device's **Inventory** tab, with filtering and CSV export. **Devices → Software** shows every title across the fleet with the versions in use, and which devices have each one.

## Live queries

Open **Devices → Live query**, write one `SELECT`, pick all devices or a group, and say why. Each device runs the query on its next check-in (about a minute) and returns up to 1,000 rows (1 MB). The console shows the combined table and each device's status. Devices that didn't check in within 10 minutes show *didn't check in*.

**Safeguards:**
- **Permission:** it needs `devices:query`, which Owners, Admins and Security analysts have. It can't be limited to groups, and it can't be granted to API keys: a query reads across the whole fleet.
- **MFA and reason:** running a query needs a recent MFA and a reason.
- **Audit:** the audit log records who ran what, with the full SQL (`device.live_query`).
- **Signed SQL:** each query reaches the device as a command signed with the organization's key, which the agent pinned at enrollment. The SQL is inside the signature, so neither a network attacker nor a tampered server response can change what runs.
- **Restricted SQL:** the server and the agent both accept only a single `SELECT` or `WITH … SELECT`. Both refuse tables that:
  - reach the network: `curl`, `curl_certificate`;
  - read file contents: `carves`, `yara`, `plist`, `augeas`;
  - collect password hashes: `shadow`;

  and they refuse `ATTACH` and `PRAGMA`.

Examples are in the editor. The [osquery schema](https://osquery.io/schema/) lists every table.

## Limits

- Results are stored with the query and aren't pruned yet.
- Column names come back sorted alphabetically, because osquery's JSON output sorts them.
- The fleet software view aggregates on request. That's fine for thousands of devices; beyond that it needs a summary table.
- No scheduled custom queries or alerting on query results yet. The pack is fixed.

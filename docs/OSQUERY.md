# osquery: inventory and live queries

The Nexus agent uses [osquery](https://osquery.io) for two things:
- **an inventory pack** it collects every 6 hours;
- **live queries**: an admin asks every device a question in SQL and gets answers within about a minute.

The installers include osquery. On a device where it's missing, for example after a hand-copied agent, devices report posture and AI tools as before, and the console explains what's missing.

## osquery comes with the agent

The Nexus installers include osquery, so an MDM rollout of the agent sets up both:

| Installer | osquery installed at |
|---|---|
| macOS `.pkg` | `/Library/Application Support/Nexus/osquery/osquery.app`, universal, left exactly as osquery signed it (Apple team `3522FA9PXF`) |
| Windows `.msi` (x64, arm64) | `C:\Program Files\Nexus\osquery\osqueryd.exe`, Authenticode-signed by osquery |
| Linux `.deb` / `.rpm` (amd64, arm64) | `/opt/nexus/osquery/osqueryd` |

**Our own location:** osquery is installed there so it never touches an osquery that you or another tool installed, and removing the agent removes it.

**Version and integrity:** [agent/packaging/osquery/osquery.lock](../agent/packaging/osquery/osquery.lock) pins the osquery version. The build downloads the official release from GitHub and stops unless each file matches the SHA-256 in the lock file. It then checks osquery's own signatures, and after packaging `verify-signatures.sh` checks the bundled copy again. To move to a new osquery version:
```bash
agent/packaging/osquery/fetch.sh update 5.24.0   # review the hashes, then commit osquery.lock
```

**Which copy the agent uses:**
1. `NEXUS_OSQUERY_PATH`;
2. the bundled copy;
3. a system install (`/usr/local/bin/osqueryi`, `C:\Program Files\osquery`, `/usr/bin/osqueryi`…).

`NEXUS_BUNDLE_OSQUERY=0 pnpm agent:release …` builds installers without it.

**How it runs:** the agent runs osquery's shell **one query at a time**, with extensions and events off and a throwaway database each time. No osquery service runs, and an existing osqueryd's configuration, database and logs are never touched.

**Updates:** agent self-updates replace only the agent. osquery changes with the next installer you deploy.

**Licence:** osquery is available under Apache-2.0 or GPL-2.0. Nexus redistributes it under Apache-2.0, and its licence text is installed next to it (`LICENSE-osquery.txt`).

**Troubleshooting on a device:**
```bash
sudo nexus-agent query "SELECT version FROM osquery_info"
```
It prints which osquery the agent uses and runs the query under the same rules as a live query.

**macOS privacy (TCC):** the pack and most tables work as installed. A few tables read folders macOS protects, for example some per-user app data. For those, grant **Full Disk Access** to the Nexus agent through a Privacy Preferences Policy Control profile in your MDM: identifier `/Library/Application Support/Nexus/bin/nexus-agent` (type *path*). The agent launches osquery, so macOS applies the agent's access.

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

## How to test it

### 1. Build the installers (on a Mac, about a minute)
```bash
pnpm agent:release 0.9.1 "osquery test"
ls agent/dist/installers        # .pkg, .deb and .rpm (amd64, arm64), each with osquery inside
```
The build downloads osquery 5.23.1 once into `agent/dist/osquery-cache`, checks every file against `osquery.lock`, and checks osquery's signatures. The Windows `.msi` is built on Windows, by CI or `build-msi.ps1 -OsqueryDir agent/dist/osquery`.

### 2. Check what's inside, without installing
```bash
pkgutil --payload-files agent/dist/installers/nexus-agent-0.9.1.pkg | grep -E "osqueryd|nexus-agent$"
agent/scripts/verify-signatures.sh agent/dist/releases/0.9.1 agent/dist/installers --mac
```
Unsigned test builds fail the Developer ID checks. That's expected; the line to look for is `bundled osquery signed by osquery`.

### 3. Linux: install in a container
```bash
docker run --rm -v "$PWD/agent/dist/installers:/pkgs:ro" ubuntu:24.04 bash -c \
  'dpkg -i /pkgs/nexus-agent_0.9.1_$(dpkg --print-architecture).deb && nexus-agent query "SELECT version FROM osquery_info"'
```
It prints `osquery 5.23.1 at /opt/nexus/osquery/osqueryd` and the version. For Fedora, run `rpm -i` on the `.rpm` in `fedora:latest`.

### 4. macOS: install on a test Mac
```bash
sudo installer -pkg agent/dist/installers/nexus-agent-0.9.1.pkg -target /
A="/Library/Application Support/Nexus/bin/nexus-agent"
sudo "$A" install --server https://api.nexus.example.com --token nxe_…
sudo "$A" query "SELECT name, version FROM apps LIMIT 5"
```
Within a minute of enrolling, the device's **Inventory** tab and **Devices → Software** fill in. `sudo "$A" uninstall` removes the agent and its bundled osquery; add `--purge` to delete the device key too.

### 5. Windows: install on a test PC (admin PowerShell)
```powershell
msiexec /i nexus-agent-0.9.1-x64.msi /qn SERVER=https://api.nexus.example.com TOKEN=nxe_…
Get-AuthenticodeSignature "C:\Program Files\Nexus\osquery\osqueryd.exe"   # Valid, OSQUERY a Series of LF Projects
& "C:\Program Files\Nexus\nexus-agent.exe" query "SELECT name, version FROM programs LIMIT 5"
```
CI runs these same checks on a clean Windows machine for every change, along with install, upgrade and uninstall.

### 6. Live query from the console
Go to **Devices → Live query**, pick an example, give a reason and run it. Confirm with MFA. Rows appear as each device checks in, usually within a minute. Then check the **Audit log** for `device.live_query`, which records the SQL you ran.

### 7. Things that must be refused
- `SELECT * FROM curl WHERE url = 'https://example.com'` in the console: refused before anything is sent.
- `sudo nexus-agent query "SELECT * FROM shadow"` on a device: refused by the agent too.
- A user without **Run live queries** (e.g. Help desk) opening Live query: sees that they lack the permission.

## Limits

- Results are stored with the query and aren't pruned yet.
- Column names come back sorted alphabetically, because osquery's JSON output sorts them.
- The fleet software view aggregates on request. That's fine for thousands of devices; beyond that it needs a summary table.
- No scheduled custom queries or alerting on query results yet. The pack is fixed.

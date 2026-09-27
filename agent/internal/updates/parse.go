// Package updates finds and installs operating-system updates: softwareupdate on macOS, Windows
// Update, and apt or dnf on Linux. Checks are slow, so they run in the background every few
// hours; installs come as signed commands from the organization's patch policy.
package updates

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Update is one pending update. A major OS upgrade (macOS 15 on 14, a Windows feature update) is
// reported but never installed by patching: that's a deliberate move, not a fix.
type Update struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Security bool   `json:"security"`
	Restart  bool   `json:"restart"`
	Upgrade  bool   `json:"upgrade,omitempty"`
	Label    string `json:"-"` // what softwareupdate installs it by
}

var (
	macLabel   = regexp.MustCompile(`^\s*\* Label: (.+)$`)
	macDetails = regexp.MustCompile(`^\s*Title: ([^,]+), Version: ([^,]+),.*$`)
)

// ParseSoftwareUpdate reads `softwareupdate -l` (macOS 10.15+). Every macOS update is treated
// as security-relevant: Apple ships security fixes in them and doesn't say which are which. A
// macOS whose major version isn't currentMajor (from sw_vers) is an upgrade, not an update.
func ParseSoftwareUpdate(out, currentMajor string) []Update {
	var ups []Update
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		m := macLabel.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		u := Update{Name: strings.TrimSpace(m[1]), Label: strings.TrimSpace(m[1]), Security: true}
		if i+1 < len(lines) {
			if d := macDetails.FindStringSubmatch(lines[i+1]); d != nil {
				u.Name, u.Version = strings.TrimSpace(d[1]), strings.TrimSpace(d[2])
			}
			u.Restart = strings.Contains(lines[i+1], "Action: restart")
		}
		if currentMajor != "" && strings.HasPrefix(u.Name, "macOS") && major(u.Version) != "" && major(u.Version) != currentMajor {
			u.Upgrade, u.Security = true, false
		}
		ups = append(ups, u)
	}
	return ups
}

func major(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	return v
}

var aptLine = regexp.MustCompile(`^([^/\s]+)/(\S+)\s+(\S+)\s+\S+`)

// ParseAptUpgradable reads `apt list --upgradable`: a package is a security update when it
// comes from a *-security suite.
func ParseAptUpgradable(out string) []Update {
	var ups []Update
	for _, l := range strings.Split(out, "\n") {
		m := aptLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		ups = append(ups, Update{Name: m[1], Version: m[3], Security: strings.Contains(m[2], "-security"), Restart: strings.HasPrefix(m[1], "linux-image")})
	}
	return ups
}

var dnfLine = regexp.MustCompile(`^(\S+)\.(\S+)\s+(\S+)\s+(\S+)\s*$`)

// ParseDnfCheckUpdate reads `dnf check-update`; security marks packages that
// `dnf updateinfo list --security` named.
func ParseDnfCheckUpdate(out string, security map[string]bool) []Update {
	var ups []Update
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Obsoleting") {
			break
		}
		m := dnfLine.FindStringSubmatch(l)
		if m == nil || m[2] == "" || strings.HasPrefix(l, "Last metadata") {
			continue
		}
		ups = append(ups, Update{Name: m[1], Version: m[3], Security: security[m[1]], Restart: strings.HasPrefix(m[1], "kernel")})
	}
	return ups
}

var dnfSec = regexp.MustCompile(`^\S+\s+\S*[Ss]ec\S*\s+(\S+)\s*$`)

// ParseDnfSecurity reads `dnf updateinfo list --security`: advisory, severity/type, package-version.
func ParseDnfSecurity(out string) map[string]bool {
	names := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if m := dnfSec.FindStringSubmatch(l); m != nil {
			// name-version-release.arch: the name is everything before the version (first "-<digit>").
			nv := m[1]
			if i := regexp.MustCompile(`-\d`).FindStringIndex(nv); i != nil {
				names[nv[:i[0]]] = true
			}
		}
	}
	return names
}

// ParseWindowsUpdates reads the JSON list our PowerShell check prints.
func ParseWindowsUpdates(out string) ([]Update, error) {
	out = strings.TrimSpace(out)
	if out == "" || out == "null" {
		return nil, nil
	}
	var raw []struct {
		Title    string `json:"Title"`
		Security bool   `json:"Security"`
		Restart  bool   `json:"Restart"`
		Upgrade  bool   `json:"Upgrade"`
	}
	if strings.HasPrefix(out, "{") {
		out = "[" + out + "]" // ConvertTo-Json prints one object without brackets
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, err
	}
	ups := make([]Update, 0, len(raw))
	for _, r := range raw {
		ups = append(ups, Update{Name: r.Title, Security: r.Security && !r.Upgrade, Restart: r.Restart, Upgrade: r.Upgrade})
	}
	return ups, nil
}

package osquery

import (
	"context"
	"time"
)

// Scheduled is one query of the inventory pack. Every OS returns the same
// columns for a name, so the server can compare devices.
type Scheduled struct {
	Name    string
	SQL     string
	MaxRows int
}

// Pack is the inventory Nexus collects on each OS.
func Pack(goos string) []Scheduled {
	var software string
	switch goos {
	case "darwin":
		software = `SELECT CASE WHEN name LIKE '%.app' THEN substr(name, 1, length(name) - 4) ELSE name END AS name, bundle_short_version AS version, 'app' AS source, bundle_identifier AS publisher FROM apps
WHERE (path LIKE '/Applications/%' OR path LIKE '/Users/%/Applications/%') AND path NOT LIKE '%.app/%'
UNION ALL SELECT name, version, 'homebrew' AS source, '' AS publisher FROM homebrew_packages`
	case "windows":
		software = `SELECT name, version, 'program' AS source, publisher FROM programs
UNION ALL SELECT name, version, 'chocolatey' AS source, '' AS publisher FROM chocolatey_packages`
	default:
		software = `SELECT name, version, 'deb' AS source, maintainer AS publisher FROM deb_packages
UNION ALL SELECT name, version || '-' || release AS version, 'rpm' AS source, vendor AS publisher FROM rpm_packages`
	}
	return []Scheduled{
		{Name: "software", SQL: software, MaxRows: 5000},
		{Name: "listening_ports", SQL: `SELECT DISTINCT COALESCE(p.name, '') AS process, l.port, CASE l.protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE CAST(l.protocol AS TEXT) END AS protocol, l.address
FROM listening_ports l LEFT JOIN processes p ON p.pid = l.pid WHERE l.port > 0`, MaxRows: 500},
		{Name: "usb_devices", SQL: `SELECT vendor, model, vendor_id, model_id, CAST(removable AS TEXT) AS removable FROM usb_devices`, MaxRows: 300},
		{Name: "browser_extensions", SQL: `SELECT e.browser_type AS browser, e.name, e.identifier, e.version, u.username AS user, e.profile FROM users u CROSS JOIN chrome_extensions e USING (uid)
UNION ALL SELECT 'firefox' AS browser, f.name, f.identifier, f.version, u.username AS user, '' AS profile FROM users u CROSS JOIN firefox_addons f USING (uid)`, MaxRows: 2000},
		{Name: "startup_items", SQL: `SELECT name, path, source, status, type FROM startup_items`, MaxRows: 1000},
	}
}

// Result of one scheduled query.
type Result struct {
	Name      string `json:"name"`
	Rows      Rows   `json:"rows"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Report is what the agent sends: the pack's results, or why there are none.
type Report struct {
	Available   bool     `json:"available"`
	Version     string   `json:"version,omitempty"`
	CollectedAt string   `json:"collected_at"`
	Results     []Result `json:"results"`
}

// Collect runs the pack. Without osquery it says so, so the console can explain.
func Collect(ctx context.Context, bin, goos string, now time.Time) Report {
	rep := Report{CollectedAt: now.UTC().Format(time.RFC3339), Results: []Result{}}
	if bin == "" {
		return rep
	}
	r := Runner{Bin: bin, Timeout: 120 * time.Second}
	rep.Version = r.Version(ctx)
	rep.Available = rep.Version != ""
	if !rep.Available {
		return rep
	}
	for _, q := range Pack(goos) {
		rows, truncated, err := r.Query(ctx, q.SQL, q.MaxRows)
		res := Result{Name: q.Name, Rows: rows, Truncated: truncated}
		if err != nil {
			res.Rows, res.Error = Rows{}, err.Error()
		}
		rep.Results = append(rep.Results, res)
	}
	return rep
}

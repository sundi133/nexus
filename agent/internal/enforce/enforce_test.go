package enforce

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var b64 = base64.RawURLEncoding

func signPolicy(t *testing.T, priv ed25519.PrivateKey, typ string, p Policy) string {
	t.Helper()
	h := b64.EncodeToString([]byte(`{"alg":"EdDSA","typ":"` + typ + `"}`))
	body, _ := json.Marshal(p)
	msg := h + "." + b64.EncodeToString(body)
	return msg + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(msg)))
}

type fixture struct {
	e      *Enforcer
	priv   ed25519.PrivateKey
	hosts  string
	procs  []Proc
	killed []int
}

func newFixture(t *testing.T) *fixture {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	f := &fixture{priv: priv, hosts: filepath.Join(dir, "hosts")}
	os.WriteFile(f.hosts, []byte("127.0.0.1 localhost\n10.0.0.5 intranet.corp # mine\n"), 0o644)
	f.e = &Enforcer{StateDir: dir, DeviceID: "dev-1", Key: func() (ed25519.PublicKey, error) { return pub, nil }, OwnHost: "api.nexus.example.com", HostsPath: f.hosts,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Processes: func() ([]Proc, error) { return f.procs, nil },
		Kill:      func(pid int) error { f.killed = append(f.killed, pid); return nil }}
	return f
}

func (f *fixture) apply(t *testing.T, ts int64, rules ...Rule) error {
	return f.e.Apply(signPolicy(t, f.priv, policyTyp, Policy{Device: "dev-1", TS: ts, Ver: ver(rules), Rules: rules}))
}

func ver(rules []Rule) string {
	b, _ := json.Marshal(rules)
	return string(b[:min(len(b), 16)]) + string(rune('a'+len(rules)))
}

func TestPolicyMustBeSignedCurrentAndOurs(t *testing.T) {
	f := newFixture(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	dom := Rule{ID: "r1", Name: "No chat", Kind: "domain", Match: "domain", Value: "chat.example.com", Mode: "block"}
	if err := f.e.Apply(signPolicy(t, other, policyTyp, Policy{Device: "dev-1", TS: 1, Rules: []Rule{dom}})); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("another key: %v", err)
	}
	if err := f.e.Apply(signPolicy(t, f.priv, "nexus-command+jwt", Policy{Device: "dev-1", TS: 1, Rules: []Rule{dom}})); err == nil {
		t.Fatal("a command signature was accepted as a policy")
	}
	if err := f.e.Apply(signPolicy(t, f.priv, policyTyp, Policy{Device: "dev-2", TS: 1, Rules: []Rule{dom}})); err == nil {
		t.Fatal("another device's policy was accepted")
	}
	if err := f.apply(t, 100, dom); err != nil {
		t.Fatal(err)
	}
	if err := f.apply(t, 50); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("a replayed older policy (without the rule) was accepted: %v", err)
	}
	if hosts, _ := os.ReadFile(f.hosts); !strings.Contains(string(hosts), "0.0.0.0 chat.example.com") {
		t.Fatalf("hosts: %s", hosts)
	}
}

func TestHostsSectionIsManagedAndEverythingElseKept(t *testing.T) {
	f := newFixture(t)
	d := func(v string) Rule { return Rule{ID: v, Kind: "domain", Match: "domain", Value: v, Mode: "block"} }
	f.apply(t, 1, d("chat.example.com"), d("mcp.example.net"), d("api.nexus.example.com"), d("example.com"))
	got, _ := os.ReadFile(f.hosts)
	want := "127.0.0.1 localhost\n10.0.0.5 intranet.corp # mine\n\n" + beginMark + "\n0.0.0.0 chat.example.com\n:: chat.example.com\n0.0.0.0 mcp.example.net\n:: mcp.example.net\n" + endMark + "\n"
	if string(got) != want {
		t.Fatalf("hosts:\n%s\nwant:\n%s", got, want) // Nexus's own host (and its parent domain) is never blocked
	}
	if s := f.e.Report().Status; s != "0 app rules (0 blocking), 2 domains blocked" {
		t.Errorf("status = %q", s)
	}
	f.apply(t, 2, d("mcp.example.net"))
	got, _ = os.ReadFile(f.hosts)
	if strings.Contains(string(got), "chat.example.com") || !strings.Contains(string(got), "mcp.example.net") || strings.Count(string(got), beginMark) != 1 {
		t.Fatalf("after replacing: %s", got)
	}
	f.apply(t, 3)
	if got, _ = os.ReadFile(f.hosts); string(got) != "127.0.0.1 localhost\n10.0.0.5 intranet.corp # mine\n" {
		t.Fatalf("after removing every rule: %q", got)
	}
	// Windows line endings survive.
	os.WriteFile(f.hosts, []byte("127.0.0.1 localhost\r\n"), 0o644)
	WriteHosts(f.hosts, []string{"x.example.com"})
	if got, _ = os.ReadFile(f.hosts); !strings.Contains(string(got), "localhost\r\n\r\n# BEGIN") || strings.Contains(strings.ReplaceAll(string(got), "\r\n", ""), "\n") {
		t.Fatalf("CRLF: %q", got)
	}
}

func TestMatching(t *testing.T) {
	sum := func(string) string { return "ab12" }
	for _, c := range []struct {
		r    Rule
		path string
		goos string
		want bool
	}{
		{Rule{Match: "name", Value: "Cursor"}, "/Applications/Cursor.app/Contents/MacOS/Cursor", "darwin", true},
		{Rule{Match: "name", Value: "cursor"}, "/Applications/Cursor.app/Contents/MacOS/Cursor", "darwin", true},
		{Rule{Match: "name", Value: "ollama"}, `C:\Users\a\AppData\Local\Programs\Ollama\ollama.exe`, "windows", true},
		{Rule{Match: "name", Value: "ollama.exe"}, "/usr/local/bin/ollama", "linux", true},
		{Rule{Match: "name", Value: "Ollama"}, "/usr/local/bin/ollama", "linux", false},
		{Rule{Match: "name", Value: "Cursor"}, "/Applications/Cursor.app/Contents/MacOS/Cursor Helper", "darwin", false},
		{Rule{Match: "path", Value: "/Applications/Claude.app/"}, "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper", "darwin", true},
		{Rule{Match: "path", Value: "/applications/claude.app/"}, "/Applications/Claude.app/Contents/MacOS/Claude", "darwin", true},
		{Rule{Match: "path", Value: "/Applications/Claude.app/"}, "/Applications/Claude.application/x", "darwin", false},
		{Rule{Match: "path", Value: "/opt/tool/bin/tool"}, "/opt/tool/bin/tool", "linux", true},
		{Rule{Match: "path", Value: `C:\Tools\`}, `c:\tools\x.exe`, "windows", true},
		{Rule{Match: "sha256", Value: "AB12"}, "/x", "linux", true},
		{Rule{Match: "sha256", Value: "cd34"}, "/x", "linux", false},
	} {
		if got := Matches(c.r, c.path, sum, c.goos); got != c.want {
			t.Errorf("%+v on %s (%s) = %v", c.r, c.path, c.goos, got)
		}
	}
}

func TestScanTerminatesOrReports(t *testing.T) {
	f := newFixture(t)
	block := Rule{ID: "b", Name: "No Ollama", Kind: "app", Match: "name", Value: "ollama", Mode: "block"}
	watch := Rule{ID: "m", Name: "Watch Claude", Kind: "app", Match: "path", Value: "/Applications/Claude.app/", Mode: "monitor"}
	careless := Rule{ID: "c", Name: "Oops", Kind: "app", Match: "name", Value: "launchd", Mode: "block"}
	f.apply(t, 1, block, watch, careless)
	f.procs = []Proc{
		{PID: 1, Path: "/sbin/launchd"},
		{PID: 300, Path: "/usr/local/bin/ollama", User: "sam"},
		{PID: 301, Path: "/Applications/Claude.app/Contents/MacOS/Claude", User: "sam"},
		{PID: 302, Path: "/Library/Application Support/Nexus/bin/ollama"}, // under Nexus's own folder: protected
		{PID: os.Getpid(), Path: "/usr/local/bin/ollama"},                 // ourselves: protected
		{PID: 303, Path: "/Applications/Safari.app/Contents/MacOS/Safari"},
	}
	f.e.Scan()
	f.e.Scan() // the monitored app is still running: still one event; the blocked one relaunched (same pid in this fake): counted
	if len(f.killed) != 2 || f.killed[0] != 300 {
		t.Fatalf("killed %v", f.killed)
	}
	rep := f.e.Report()
	byAction := map[string]Event{}
	for _, ev := range rep.Events {
		byAction[ev.Action] = ev
	}
	if ev := byAction["terminated"]; ev.RuleID != "b" || ev.Count != 2 || ev.User != "sam" || ev.Subject != "/usr/local/bin/ollama" {
		t.Errorf("terminated = %+v", ev)
	}
	if ev := byAction["would_terminate"]; ev.RuleID != "m" || ev.Count != 1 {
		t.Errorf("would_terminate = %+v", ev)
	}
	if len(rep.Events) != 2 {
		t.Fatalf("events = %+v", rep.Events)
	}
	// Delivered: gone; the monitored app, still running, isn't reported again.
	f.e.Delivered(rep)
	f.e.Scan()
	for _, ev := range f.e.Report().Events {
		if ev.Action == "would_terminate" {
			t.Fatalf("reported the same running app again: %+v", ev)
		}
	}
	// A new launch of the monitored app is a new event.
	f.procs = append(f.procs[:2], Proc{PID: 401, Path: "/Applications/Claude.app/Contents/MacOS/Claude"})
	f.e.Scan()
	found := false
	for _, ev := range f.e.Report().Events {
		found = found || ev.Action == "would_terminate"
	}
	if !found {
		t.Fatal("a new launch wasn't reported")
	}
}

func TestKillFailureIsReported(t *testing.T) {
	f := newFixture(t)
	f.e.Kill = func(int) error { return errors.New("access denied") }
	f.apply(t, 1, Rule{ID: "b", Kind: "app", Match: "name", Value: "x", Mode: "block"})
	f.procs = []Proc{{PID: 50, Path: "/opt/x"}}
	f.e.Scan()
	if ev := f.e.Report().Events; len(ev) != 1 || ev[0].Action != "failed" || !strings.Contains(ev[0].Detail, "access denied") {
		t.Fatalf("events = %+v", ev)
	}
}

func TestRulesSurviveARestart(t *testing.T) {
	f := newFixture(t)
	f.apply(t, 7, Rule{ID: "d", Kind: "domain", Match: "domain", Value: "chat.example.com", Mode: "block"})
	os.WriteFile(f.hosts, []byte("127.0.0.1 localhost\n"), 0o644) // someone edited the hosts file
	g := &Enforcer{StateDir: f.e.StateDir, DeviceID: "dev-1", Key: f.e.Key, HostsPath: f.hosts, Log: f.e.Log}
	g.Load()
	if hosts, _ := os.ReadFile(f.hosts); !strings.Contains(string(hosts), "chat.example.com") {
		t.Fatalf("after restart: %s", hosts)
	}
	// …and an older policy is still refused after the restart.
	if err := g.Apply(signPolicy(t, f.priv, policyTyp, Policy{Device: "dev-1", TS: 3})); err == nil {
		t.Fatal("older policy accepted after restart")
	}
}

func TestHostsWrittenInPlaceWhenItCantBeReplaced(t *testing.T) {
	f := newFixture(t)
	rename = func(string, string) error { return errors.New("device or resource busy") }
	defer func() { rename = os.Rename }()
	f.apply(t, 1, Rule{ID: "d", Kind: "domain", Match: "domain", Value: "chat.example.com", Mode: "block"})
	if hosts, _ := os.ReadFile(f.hosts); !strings.Contains(string(hosts), "0.0.0.0 chat.example.com") || !strings.HasPrefix(string(hosts), "127.0.0.1 localhost") {
		t.Fatalf("hosts: %s", hosts)
	}
	if s := f.e.Report().Status; !strings.Contains(s, "1 domains blocked") {
		t.Fatalf("status = %q", s)
	}
}

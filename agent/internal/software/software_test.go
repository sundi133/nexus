package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type exitErr int

func (e exitErr) Error() string { return "exit status" }
func (e exitErr) ExitCode() int { return int(e) }

// fake is a device: which refs are installed, and every command run.
type fake struct {
	installed map[string]bool
	ran       []string
	fail      map[string]error // command prefix → error
}

func (f *fake) sys(goos string) Sys {
	return Sys{
		GOOS: goos,
		Has:  func(string) bool { return true },
		Winget: func() string {
			return `C:\winget.exe`
		},
		Download: func(_ context.Context, u, sum, dir string) (string, error) {
			f.ran = append(f.ran, "download "+u)
			return dir + "/installer", nil
		},
		Dir: "/tmp/nexus-dl",
		Run: func(_ context.Context, name string, args ...string) (string, error) {
			cmd := strings.Join(append([]string{name}, args...), " ")
			f.ran = append(f.ran, cmd)
			for p, err := range f.fail {
				if strings.HasPrefix(cmd, p) {
					return "boom", err
				}
			}
			ref := ""
			switch {
			case name == "pkgutil", name == "rpm":
				ref = args[len(args)-1]
				if !f.installed[ref] {
					return "", exitErr(1)
				}
				return "ok", nil
			case name == "dpkg-query":
				if f.installed[args[len(args)-1]] {
					return "install ok installed", nil
				}
				return "", exitErr(1)
			case name == "reg":
				k := args[1]
				if f.installed[k[strings.LastIndex(k, `\`)+1:]] {
					return "found", nil
				}
				return "", exitErr(1)
			case strings.HasSuffix(name, "winget.exe") && args[0] == "list":
				if f.installed[args[2]] {
					return "Name Id Version\nZoom Zoom.Zoom 6.1", nil
				}
				return "No installed package found", exitErr(0x8A150014)
			}
			// installs and removals flip the state
			switch {
			case strings.HasSuffix(name, "winget.exe"):
				f.installed[args[2]] = args[0] == "install"
			case name == "msiexec" && args[0] == "/x":
				f.installed[args[1]] = false
			case name == "msiexec":
				f.installed["{11111111-2222-3333-4444-555555555555}"] = true
				return "", exitErr(3010)
			case name == "installer":
				f.installed["us.zoom.pkg.videomeeting"] = true
			case name == "env":
				f.installed[args[len(args)-1]] = strings.Contains(cmd, " install ")
			case name == "dnf":
				f.installed[args[len(args)-1]] = args[0] == "install"
			}
			return "done", nil
		},
		Now: func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) },
	}
}

func TestInstallsAndRemovesPerKind(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		goos string
		it   Item
		want string // a command that must have run
	}{
		{"windows", Item{ID: "1", Action: "install", Kind: "winget", Ref: "Zoom.Zoom"}, `C:\winget.exe install --id Zoom.Zoom --exact --silent --scope machine`},
		{"windows", Item{ID: "2", Action: "install", Kind: "msi", Ref: "{11111111-2222-3333-4444-555555555555}", URL: "https://example.com/app.msi", SHA256: strings.Repeat("a", 64), Args: []string{"ALLUSERS=1"}}, "msiexec /i /tmp/nexus-dl/installer /qn /norestart ALLUSERS=1"},
		{"darwin", Item{ID: "3", Action: "install", Kind: "pkg", Ref: "us.zoom.pkg.videomeeting", URL: "https://example.com/zoom.pkg", SHA256: strings.Repeat("b", 64)}, "installer -pkg /tmp/nexus-dl/installer -target /"},
		{"linux", Item{ID: "4", Action: "install", Kind: "apt", Ref: "htop"}, "env DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o Dpkg::Options::=--force-confold htop"},
		{"linux", Item{ID: "5", Action: "install", Kind: "dnf", Ref: "htop"}, "dnf install -y -q htop"},
	} {
		f := &fake{installed: map[string]bool{}}
		r := f.sys(tc.goos).Reconcile(ctx, tc.it)
		if r.Status != Installed || !strings.Contains(strings.Join(f.ran, "\n"), tc.want) {
			t.Errorf("%s: %+v, ran %q", tc.it.Kind, r, f.ran)
		}
		// Already there: nothing runs but the check.
		f.ran = nil
		if r := f.sys(tc.goos).Reconcile(ctx, tc.it); r.Status != Installed || len(f.ran) > 2 {
			t.Errorf("%s again: %+v, ran %q", tc.it.Kind, r, f.ran)
		}
		if tc.it.Kind == "pkg" {
			continue
		}
		rm := tc.it
		rm.Action = "remove"
		if r := f.sys(tc.goos).Reconcile(ctx, rm); r.Status != Absent {
			t.Errorf("%s remove: %+v, ran %q", tc.it.Kind, r, f.ran)
		}
	}
}

func TestRefusesWhatCouldInjectOrIsUnverified(t *testing.T) {
	f := &fake{installed: map[string]bool{}}
	for _, it := range []Item{
		{ID: "a", Action: "install", Kind: "apt", Ref: "--allow-unauthenticated"},
		{ID: "b", Action: "install", Kind: "winget", Ref: "Zoom.Zoom --override"},
		{ID: "c", Action: "install", Kind: "msi", Ref: "{11111111-2222-3333-4444-555555555555}", URL: "http://example.com/app.msi", SHA256: strings.Repeat("a", 64)},
		{ID: "d", Action: "install", Kind: "pkg", Ref: "com.example", URL: "https://example.com/a.pkg"},
		{ID: "e", Action: "install", Kind: "dnf", Ref: "htop", Args: []string{"x\ny"}},
	} {
		if r := f.sys("linux").Reconcile(context.Background(), it); r.Status != Failed || !strings.HasPrefix(r.Detail, "refused") {
			t.Errorf("%s: %+v", it.ID, r)
		}
	}
	if len(f.ran) != 0 {
		t.Fatalf("ran %q", f.ran)
	}
	// The wrong OS, and a pkg removal, are unsupported, not failures.
	if r := f.sys("linux").Reconcile(context.Background(), Item{ID: "x", Action: "install", Kind: "winget", Ref: "Zoom.Zoom"}); r.Status != Unsupported {
		t.Fatalf("%+v", r)
	}
	if r := f.sys("darwin").Reconcile(context.Background(), Item{ID: "y", Action: "remove", Kind: "pkg", Ref: "com.example"}); r.Status != Unsupported {
		t.Fatalf("%+v", r)
	}
}

func TestInstallerThatDoesNothingIsAFailure(t *testing.T) {
	f := &fake{installed: map[string]bool{}}
	s := f.sys("linux")
	inner := s.Run
	s.Run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "env" {
			return "ok", nil // claims success, installs nothing
		}
		return inner(ctx, name, args...)
	}
	if r := s.Reconcile(context.Background(), Item{ID: "1", Action: "install", Kind: "apt", Ref: "htop"}); r.Status != Failed || !strings.Contains(r.Detail, "isn't detected") {
		t.Fatalf("%+v", r)
	}
}

func TestFailuresWaitBeforeRetrying(t *testing.T) {
	f := &fake{installed: map[string]bool{}, fail: map[string]error{"dnf install": exitErr(1)}}
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	s := f.sys("linux")
	s.Now = func() time.Time { return now }
	m := &Manager{Sys: s}
	it := Item{ID: "1", Action: "install", Kind: "dnf", Ref: "htop"}
	if r := m.Apply(context.Background(), []Item{it}); r[0].Status != Failed || r[0].Detail != "boom" {
		t.Fatalf("%+v", r)
	}
	n := len(f.ran)
	now = now.Add(time.Hour)
	if r := m.Apply(context.Background(), []Item{it}); r[0].Status != Failed || len(f.ran) != n {
		t.Fatalf("retried too soon: %+v %q", r, f.ran[n:])
	}
	// A changed item is tried at once; so is the old one after RetryAfter.
	it2 := it
	it2.Args = []string{"--setopt=install_weak_deps=False"}
	m.Apply(context.Background(), []Item{it2})
	if len(f.ran) == n {
		t.Fatal("a changed item wasn't tried")
	}
	delete(f.fail, "dnf install")
	now = now.Add(RetryAfter)
	if r := m.Apply(context.Background(), []Item{it}); r[0].Status != Installed {
		t.Fatalf("%+v", r)
	}
}

func TestDownloadChecksTheHash(t *testing.T) {
	body := []byte("installer bytes")
	sum := sha256.Sum256(body)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer srv.Close()
	old := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport // trust the test certificate
	defer func() { http.DefaultTransport = old }()
	dir := t.TempDir()
	p, err := Download(context.Background(), srv.URL+"/app.msi", hex.EncodeToString(sum[:]), dir)
	if err != nil || !strings.HasSuffix(p, ".msi") {
		t.Fatalf("%q %v", p, err)
	}
	if b, _ := os.ReadFile(p); string(b) != string(body) {
		t.Fatal("wrong content")
	}
	if _, err := Download(context.Background(), srv.URL+"/app.msi", strings.Repeat("0", 64), dir); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("accepted a mismatched download: %v", err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 1 {
		t.Fatalf("a rejected download was left behind: %d files", len(left))
	}
	if _, err := Download(context.Background(), "http://example.com/a.msi", strings.Repeat("0", 64), dir); err == nil {
		t.Fatal("accepted http")
	}
}

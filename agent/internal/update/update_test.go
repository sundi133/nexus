package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/votal-ai/nexus/agent/internal/release"
)

type fixture struct {
	t        *testing.T
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	dir      string
	exe      string
	served   []byte // what the "server" returns for the download
	selftest error
	now      time.Time
}

func newFixture(t *testing.T) *fixture {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	exe := filepath.Join(dir, "nexus-agent")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, priv: priv, pub: pub, dir: dir, exe: exe, now: time.Unix(1_800_000_000, 0)}
}

func (f *fixture) updater(current string) *Updater {
	return &Updater{
		Keys: []ed25519.PublicKey{f.pub}, Current: current, Exe: f.exe, StateDir: filepath.Join(f.dir, "state"),
		Download: func(_ context.Context, _ string, _ int64) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(f.served)), nil
		},
		SelfTest: func(context.Context, string, string) error { return f.selftest },
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      func() time.Time { return f.now },
	}
}

// offer signs `content` as release `version` for this platform.
func (f *fixture) offer(version string, content []byte) release.Offer {
	sum := sha256.Sum256(content)
	h := hex.EncodeToString(sum[:])
	kid, sig := release.Sign(f.priv, version, runtime.GOOS, runtime.GOARCH, h, int64(len(content)))
	f.served = content
	return release.Offer{Version: version, URL: "/v1/agent/releases/" + version + "/bin", SHA256: h, Size: int64(len(content)), KeyID: kid, Signature: sig}
}

func (f *fixture) exeIs(want string) {
	f.t.Helper()
	got, _ := os.ReadFile(f.exe)
	if string(got) != want {
		f.t.Fatalf("binary is %q, want %q", got, want)
	}
}

func TestInstallsVerifiedUpdateAndCommitsAfterCheckIn(t *testing.T) {
	f := newFixture(t)
	if err := f.updater("0.1.0").Apply(context.Background(), f.offer("0.2.0", []byte("new binary"))); !errors.Is(err, ErrRestart) {
		t.Fatalf("Apply = %v", err)
	}
	f.exeIs("new binary")
	if prev, _ := os.ReadFile(f.exe + ".previous"); string(prev) != "old binary" {
		t.Fatalf("previous = %q", prev)
	}
	// The restarted (new) binary.
	u := f.updater("0.2.0")
	if err := u.Recover(); err != nil {
		t.Fatal(err)
	}
	if u.Result() != nil {
		t.Fatal("nothing to report before the first check-in")
	}
	if err := u.Health(true); err != nil {
		t.Fatal(err)
	}
	if r := u.Result(); r == nil || *r != (release.Result{Version: "0.2.0", State: "installed"}) {
		t.Fatalf("result = %+v", r)
	}
	u.ClearResult(u.Result())
	if u.Result() != nil {
		t.Fatal("result not cleared after reporting")
	}
	// Later restarts are normal restarts.
	if err := u.Recover(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsBadUpdatesWithoutTouchingTheBinary(t *testing.T) {
	cases := map[string]func(f *fixture) release.Offer{
		"tampered download": func(f *fixture) release.Offer {
			o := f.offer("0.2.0", []byte("new binary"))
			f.served = []byte("evil binary") // wrong length is caught first; same length below
			return o
		},
		"same-size tampering": func(f *fixture) release.Offer {
			o := f.offer("0.2.0", []byte("new binary"))
			f.served = []byte("evl binary")
			f.served = append(f.served, '!')
			return o
		},
		"oversized download": func(f *fixture) release.Offer {
			o := f.offer("0.2.0", []byte("new binary"))
			f.served = []byte("new binary plus more")
			return o
		},
		"unsigned": func(f *fixture) release.Offer {
			o := f.offer("0.2.0", []byte("new binary"))
			o.Signature = o.Signature[:10] + "AAAA" + o.Signature[14:]
			return o
		},
		"signed for another version": func(f *fixture) release.Offer {
			o := f.offer("0.2.0", []byte("new binary"))
			o.Version = "0.3.0"
			return o
		},
		"downgrade":    func(f *fixture) release.Offer { return f.offer("0.0.9", []byte("old-ish")) },
		"same version": func(f *fixture) release.Offer { return f.offer("0.1.0", []byte("same")) },
		"foreign URL": func(f *fixture) release.Offer {
			o := f.offer("0.2.0", []byte("new binary"))
			o.URL = "https://evil.example.com/x"
			return o
		},
		"fails self-test": func(f *fixture) release.Offer {
			f.selftest = errors.New("exit status 1")
			return f.offer("0.2.0", []byte("new binary"))
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			u := f.updater("0.1.0")
			o := mk(f)
			err := u.Apply(context.Background(), o)
			if err == nil || errors.Is(err, ErrRestart) {
				t.Fatalf("Apply = %v, want a failure", err)
			}
			f.exeIs("old binary")
			if r := u.Result(); r == nil || r.State != "failed" || r.Version != o.Version {
				t.Fatalf("result = %+v", r)
			}
			if _, err := os.Stat(u.pendingPath()); err == nil {
				t.Fatal("pending update left behind")
			}
			// Not retried every minute.
			if err := u.Apply(context.Background(), o); err != nil {
				t.Fatalf("second attempt = %v, want skipped", err)
			}
			leftovers, _ := filepath.Glob(filepath.Join(f.dir, ".nexus-agent-*"))
			if len(leftovers) != 0 {
				t.Fatalf("download left behind: %v", leftovers)
			}
		})
	}
}

func TestNoReleaseKeysMeansNoUpdates(t *testing.T) {
	f := newFixture(t)
	u := f.updater("0.1.0")
	u.Keys = nil
	if err := u.Apply(context.Background(), f.offer("0.2.0", []byte("new binary"))); err == nil {
		t.Fatal("update applied without release keys")
	}
	f.exeIs("old binary")
}

func TestRollsBackACrashLoopingRelease(t *testing.T) {
	f := newFixture(t)
	if err := f.updater("0.1.0").Apply(context.Background(), f.offer("0.2.0", []byte("new binary"))); !errors.Is(err, ErrRestart) {
		t.Fatal(err)
	}
	// The new binary starts, then dies before its first check-in; the service manager restarts it.
	for i := 1; i <= MaxBoots; i++ {
		if err := f.updater("0.2.0").Recover(); err != nil {
			t.Fatalf("boot %d: %v", i, err)
		}
	}
	u := f.updater("0.2.0")
	if err := u.Recover(); !errors.Is(err, ErrRestart) {
		t.Fatalf("boot %d: Recover = %v, want rollback", MaxBoots+1, err)
	}
	f.exeIs("old binary")
	r := u.Result()
	if r == nil || r.State != "rolled_back" || r.Version != "0.2.0" {
		t.Fatalf("result = %+v", r)
	}
	// The restored binary starts cleanly and reports the rollback.
	old := f.updater("0.1.0")
	if err := old.Recover(); err != nil {
		t.Fatal(err)
	}
	if r := old.Result(); r == nil || r.State != "rolled_back" {
		t.Fatalf("old binary sees result %+v", r)
	}
}

func TestRollsBackWhenTheNewVersionCantCheckIn(t *testing.T) {
	f := newFixture(t)
	_ = f.updater("0.1.0").Apply(context.Background(), f.offer("0.2.0", []byte("new binary")))
	u := f.updater("0.2.0")
	_ = u.Recover()
	if err := u.Health(false); err != nil {
		t.Fatalf("early failure = %v, want patience", err)
	}
	f.now = f.now.Add(Deadline + time.Second)
	if err := u.Health(false); !errors.Is(err, ErrRestart) {
		t.Fatalf("Health after deadline = %v, want rollback", err)
	}
	f.exeIs("old binary")
	if r := u.Result(); r == nil || r.State != "rolled_back" {
		t.Fatalf("result = %+v", r)
	}
}

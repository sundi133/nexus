// Package update installs signed agent releases and rolls back bad ones (DEV-07).
//
// Apply: verify the offer's signature with the release keys compiled into
// this binary → download (exact size) → check SHA-256 → run the new binary's
// `selftest` → swap it in atomically, keeping the old one as .previous →
// restart. After the restart the new binary must check in successfully
// within Deadline and must not crash-loop (MaxBoots); otherwise it restores
// .previous and restarts into it. Every outcome is reported to the server.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/votal-ai/nexus/agent/internal/release"
)

// ErrRestart asks the caller to restart the process into the binary now on disk.
var ErrRestart = errors.New("restart into the updated agent")

const (
	MaxBoots = 3
	Deadline = 10 * time.Minute
)

type pending struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Boots     int       `json:"boots"`
	StartedAt time.Time `json:"started_at"`
}

type Updater struct {
	Keys     []ed25519.PublicKey
	Current  string // version of the running binary
	Exe      string // path of the running binary
	StateDir string
	// Download fetches a server path, returning at most max bytes.
	Download func(ctx context.Context, path string, max int64) (io.ReadCloser, error)
	// SelfTest runs a candidate binary and checks it reports the expected version.
	SelfTest func(ctx context.Context, path, version string) error
	Log      *slog.Logger
	Now      func() time.Time

	mu     sync.Mutex
	failed map[string]bool // versions that failed in this process: don't retry every minute
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) pendingPath() string { return filepath.Join(u.StateDir, "update-pending.json") }
func (u *Updater) resultPath() string  { return filepath.Join(u.StateDir, "update-result.json") }
func (u *Updater) previous() string    { return u.Exe + ".previous" }

// Apply installs an offered release. It returns ErrRestart once the new binary is in place.
func (u *Updater) Apply(ctx context.Context, o release.Offer) error {
	u.mu.Lock()
	if u.failed[o.Version] {
		u.mu.Unlock()
		return nil
	}
	u.mu.Unlock()
	if err := u.apply(ctx, o); err != nil {
		if errors.Is(err, ErrRestart) {
			return err
		}
		u.Log.Error("update failed", "version", o.Version, "err", err)
		u.mu.Lock()
		if u.failed == nil {
			u.failed = map[string]bool{}
		}
		u.failed[o.Version] = true
		u.mu.Unlock()
		u.writeResult(release.Result{Version: o.Version, State: "failed", Error: err.Error()})
		return err
	}
	return nil
}

func (u *Updater) apply(ctx context.Context, o release.Offer) error {
	if release.Compare(o.Version, u.Current) <= 0 {
		return fmt.Errorf("refusing to move from %s to %s: not newer", u.Current, o.Version)
	}
	if len(u.Keys) == 0 {
		return errors.New("this agent build has no release keys, so it can't verify updates")
	}
	a := release.Artifact{OS: runtime.GOOS, Arch: runtime.GOARCH, SHA256: strings.ToLower(o.SHA256), Size: o.Size, KeyID: o.KeyID, Signature: o.Signature}
	if err := release.Verify(u.Keys, o.Version, a); err != nil {
		return err
	}
	if o.Size <= 0 || o.Size > 512<<20 {
		return fmt.Errorf("implausible size %d", o.Size)
	}
	if !strings.HasPrefix(o.URL, "/") || strings.HasPrefix(o.URL, "//") {
		return fmt.Errorf("download must be a path on the Nexus server, got %q", o.URL)
	}
	u.Log.Info("downloading update", "version", o.Version, "bytes", o.Size)

	tmp := filepath.Join(filepath.Dir(u.Exe), fmt.Sprintf(".nexus-agent-%s.download", o.Version))
	if err := u.fetch(ctx, o, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := u.SelfTest(ctx, tmp, o.Version); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("new binary failed its self-test: %w", err)
	}

	// Record intent first: whatever happens next, the next start knows how to judge (and undo) it.
	if err := u.savePending(pending{From: u.Current, To: o.Version, StartedAt: u.now()}); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(u.previous())
	if err := os.Rename(u.Exe, u.previous()); err != nil {
		_ = os.Remove(tmp)
		_ = os.Remove(u.pendingPath())
		return fmt.Errorf("couldn't set the current binary aside: %w", err)
	}
	if err := os.Rename(tmp, u.Exe); err != nil {
		_ = os.Rename(u.previous(), u.Exe)
		_ = os.Remove(tmp)
		_ = os.Remove(u.pendingPath())
		return fmt.Errorf("couldn't install the new binary: %w", err)
	}
	u.Log.Info("update installed; restarting", "from", u.Current, "to", o.Version)
	return ErrRestart
}

func (u *Updater) fetch(ctx context.Context, o release.Offer, dst string) error {
	body, err := u.Download(ctx, o.URL, o.Size)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer body.Close()
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	// Read one byte more than promised so an oversized download is detected, not truncated.
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, o.Size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	if n != o.Size {
		return fmt.Errorf("download is %d bytes, expected %d", n, o.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != strings.ToLower(o.SHA256) {
		return fmt.Errorf("download doesn't match the signed checksum (got %s)", got[:12])
	}
	return os.Chmod(dst, 0o755)
}

// Recover runs at startup. It counts boots of a freshly installed binary and
// rolls back to the previous one when the new one keeps failing.
func (u *Updater) Recover() error {
	p, err := u.loadPending()
	if err != nil || p == nil {
		return err
	}
	switch u.Current {
	case p.To:
		p.Boots++
		if p.Boots > MaxBoots {
			return u.rollback(*p, fmt.Sprintf("%s restarted %d times without checking in", p.To, p.Boots-1))
		}
		if u.now().Sub(p.StartedAt) > Deadline {
			return u.rollback(*p, fmt.Sprintf("%s didn't check in within %s", p.To, Deadline))
		}
		return u.savePending(*p)
	default:
		// We're not the binary the pending update installed (it was rolled back
		// or replaced by hand): nothing left to judge.
		return os.Remove(u.pendingPath())
	}
}

// Health is called after every check-in. The first success on a new version
// commits it; failing past the deadline rolls it back (returns ErrRestart).
func (u *Updater) Health(ok bool) error {
	p, err := u.loadPending()
	if err != nil || p == nil || p.To != u.Current {
		return err
	}
	if ok {
		u.Log.Info("update verified", "version", u.Current)
		u.writeResult(release.Result{Version: u.Current, State: "installed"})
		return os.Remove(u.pendingPath())
	}
	if u.now().Sub(p.StartedAt) > Deadline {
		return u.rollback(*p, fmt.Sprintf("%s couldn't check in for %s", p.To, Deadline))
	}
	return nil
}

func (u *Updater) rollback(p pending, reason string) error {
	u.Log.Error("rolling back update", "from", p.To, "to", p.From, "reason", reason)
	if _, err := os.Stat(u.previous()); err != nil {
		_ = os.Remove(u.pendingPath())
		return fmt.Errorf("can't roll back, previous binary missing: %w", err)
	}
	failed := u.Exe + ".failed"
	_ = os.Remove(failed)
	if err := os.Rename(u.Exe, failed); err != nil {
		return err
	}
	if err := os.Rename(u.previous(), u.Exe); err != nil {
		_ = os.Rename(failed, u.Exe)
		return err
	}
	u.writeResult(release.Result{Version: p.To, State: "rolled_back", Error: reason})
	_ = os.Remove(u.pendingPath())
	return ErrRestart
}

// Result returns an update outcome not yet reported to the server.
func (u *Updater) Result() *release.Result {
	raw, err := os.ReadFile(u.resultPath())
	if err != nil {
		return nil
	}
	var r release.Result
	if json.Unmarshal(raw, &r) != nil {
		return nil
	}
	return &r
}

// ClearResult is called once the server has accepted the report.
func (u *Updater) ClearResult(reported *release.Result) {
	if cur := u.Result(); cur != nil && reported != nil && *cur == *reported {
		_ = os.Remove(u.resultPath())
	}
}

func (u *Updater) writeResult(r release.Result) {
	data, _ := json.Marshal(r)
	if err := writeAtomic(u.resultPath(), data); err != nil {
		u.Log.Warn("couldn't save the update result", "err", err)
	}
}

func (u *Updater) loadPending() (*pending, error) {
	raw, err := os.ReadFile(u.pendingPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p pending
	if err := json.Unmarshal(raw, &p); err != nil {
		_ = os.Remove(u.pendingPath())
		return nil, nil
	}
	return &p, nil
}

func (u *Updater) savePending(p pending) error {
	data, _ := json.Marshal(p)
	return writeAtomic(u.pendingPath(), data)
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ExecSelfTest runs `<binary> selftest` and checks the version it prints.
func ExecSelfTest(ctx context.Context, path, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "selftest").Output()
	if err != nil {
		return err
	}
	if got := strings.TrimSpace(string(out)); got != version {
		return fmt.Errorf("it reports version %q, expected %q", got, version)
	}
	return nil
}

// Package software installs and removes apps the organization assigns to this device (like
// JumpCloud Software Management): winget and MSI on Windows, .pkg on macOS, apt and dnf on Linux.
// The list arrives in the signed device policy; the agent makes the device match it in the
// background and reports each app's state. Downloads must be HTTPS and match the SHA-256 the
// policy carries, so neither the network nor the download host can swap the installer.
package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Item is one app the policy wants installed or removed.
type Item struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Action string   `json:"action"` // install | remove
	Kind   string   `json:"kind"`   // winget | msi | pkg | apt | dnf
	Ref    string   `json:"ref"`    // winget ID, MSI ProductCode, pkg receipt ID, or package name
	URL    string   `json:"url,omitempty"`
	SHA256 string   `json:"sha256,omitempty"`
	Args   []string `json:"args,omitempty"`
}

// Result is what the agent reports for an item.
type Result struct {
	ID     string `json:"id"`
	Status string `json:"status"` // installed | absent | failed | unsupported
	Detail string `json:"detail,omitempty"`
	At     string `json:"at"`
}

const (
	Installed   = "installed"
	Absent      = "absent"
	Failed      = "failed"
	Unsupported = "unsupported"
)

// Sys is how the package touches the device (faked in tests).
type Sys struct {
	GOOS string
	// Run executes a command and returns its combined output; a non-zero exit is an error with ExitCode().
	Run func(ctx context.Context, name string, args ...string) (string, error)
	Has func(name string) bool
	// Winget finds winget.exe (as SYSTEM it isn't on the PATH); "" when there's none.
	Winget func() string
	// Download fetches url into dir and checks its SHA-256; the caller removes the file.
	Download func(ctx context.Context, url, sha256, dir string) (string, error)
	Dir      string
	Now      func() time.Time
}

var refOK = map[string]*regexp.Regexp{
	"winget": regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$`),
	"msi":    regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`),
	"pkg":    regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`),
	"apt":    regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{0,127}$`),
	"dnf":    regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`),
}

var kindOS = map[string]string{"winget": "windows", "msi": "windows", "pkg": "darwin", "apt": "linux", "dnf": "linux"}

var sha = regexp.MustCompile(`^[0-9a-f]{64}$`)

// check refuses an item the agent must not act on, whatever signed it: a bad reference could
// smuggle an option into the package manager's command line.
func check(it Item) error {
	re, ok := refOK[it.Kind]
	if !ok {
		return fmt.Errorf("unknown kind %q", it.Kind)
	}
	if !re.MatchString(it.Ref) {
		return fmt.Errorf("invalid %s reference %q", it.Kind, it.Ref)
	}
	if it.Action != "install" && it.Action != "remove" {
		return fmt.Errorf("unknown action %q", it.Action)
	}
	if it.Kind == "msi" || it.Kind == "pkg" {
		if it.Action == "install" {
			u, err := url.Parse(it.URL)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return errors.New("the installer URL must be https")
			}
			if !sha.MatchString(it.SHA256) {
				return errors.New("the installer needs its SHA-256")
			}
		}
	}
	for _, a := range it.Args {
		if a == "" || len(a) > 500 || strings.ContainsAny(a, "\r\n\x00") {
			return errors.New("invalid installer argument")
		}
	}
	return nil
}

func exitCode(err error) int {
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	return -1
}

func short(out string, err error) string {
	out = strings.TrimSpace(out)
	if lines := strings.Split(out, "\n"); len(lines) > 0 {
		out = strings.TrimSpace(lines[len(lines)-1])
	}
	if out == "" && err != nil {
		out = err.Error()
	}
	if len(out) > 300 {
		out = out[:300]
	}
	return out
}

func (s Sys) winget() (string, error) {
	if s.Winget != nil {
		if p := s.Winget(); p != "" {
			return p, nil
		}
	}
	return "", errors.New("winget (App Installer) isn't on this device")
}

// Present says whether the item is installed.
func (s Sys) Present(ctx context.Context, it Item) (bool, error) {
	switch it.Kind {
	case "winget":
		w, err := s.winget()
		if err != nil {
			return false, err
		}
		out, _ := s.Run(ctx, w, "list", "--id", it.Ref, "--exact", "--accept-source-agreements", "--disable-interactivity")
		return strings.Contains(strings.ToLower(out), strings.ToLower(it.Ref)), nil
	case "msi":
		for _, k := range []string{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\`} {
			if _, err := s.Run(ctx, "reg", "query", k+it.Ref); err == nil {
				return true, nil
			}
		}
		return false, nil
	case "pkg":
		_, err := s.Run(ctx, "pkgutil", "--pkg-info", it.Ref)
		return err == nil, nil
	case "apt":
		out, _ := s.Run(ctx, "dpkg-query", "-W", "-f=${Status}", it.Ref)
		return strings.Contains(out, "install ok installed"), nil
	case "dnf":
		_, err := s.Run(ctx, "rpm", "-q", it.Ref)
		return err == nil, nil
	}
	return false, fmt.Errorf("unknown kind %q", it.Kind)
}

func (s Sys) install(ctx context.Context, it Item) error {
	var out string
	var err error
	switch it.Kind {
	case "winget":
		w, werr := s.winget()
		if werr != nil {
			return werr
		}
		out, err = s.Run(ctx, w, append([]string{"install", "--id", it.Ref, "--exact", "--silent", "--scope", "machine", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"}, it.Args...)...)
	case "msi", "pkg":
		f, derr := s.Download(ctx, it.URL, it.SHA256, s.Dir)
		if derr != nil {
			return derr
		}
		defer os.Remove(f)
		if it.Kind == "msi" {
			out, err = s.Run(ctx, "msiexec", append([]string{"/i", f, "/qn", "/norestart"}, it.Args...)...)
			if exitCode(err) == 3010 { // installed; a restart finishes it
				err = nil
			}
		} else {
			out, err = s.Run(ctx, "installer", append([]string{"-pkg", f, "-target", "/"}, it.Args...)...)
		}
	case "apt":
		out, err = s.Run(ctx, "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-q", "-o", "Dpkg::Options::=--force-confold"}, append(it.Args, it.Ref)...)...)
	case "dnf":
		out, err = s.Run(ctx, "dnf", append([]string{"install", "-y", "-q"}, append(it.Args, it.Ref)...)...)
	}
	if err != nil {
		return errors.New(short(out, err))
	}
	return nil
}

func (s Sys) remove(ctx context.Context, it Item) error {
	var out string
	var err error
	switch it.Kind {
	case "winget":
		w, werr := s.winget()
		if werr != nil {
			return werr
		}
		out, err = s.Run(ctx, w, "uninstall", "--id", it.Ref, "--exact", "--silent", "--accept-source-agreements", "--disable-interactivity")
	case "msi":
		out, err = s.Run(ctx, "msiexec", "/x", it.Ref, "/qn", "/norestart")
		if c := exitCode(err); c == 3010 || c == 1605 { // removed (restart pending) / wasn't installed
			err = nil
		}
	case "apt":
		out, err = s.Run(ctx, "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "remove", "-y", "-q", it.Ref)
	case "dnf":
		out, err = s.Run(ctx, "dnf", "remove", "-y", "-q", it.Ref)
	}
	if err != nil {
		return errors.New(short(out, err))
	}
	return nil
}

// InstallTimeout bounds one install or removal.
const InstallTimeout = 30 * time.Minute

// RetryAfter is how long a failed item waits before the agent tries it again (unless it changes).
const RetryAfter = 6 * time.Hour

// Reconcile makes one item match the policy and says where it stands.
func (s Sys) Reconcile(ctx context.Context, it Item) Result {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	r := Result{ID: it.ID, At: now().UTC().Format(time.RFC3339)}
	if err := check(it); err != nil {
		r.Status, r.Detail = Failed, "refused: "+err.Error()
		return r
	}
	if kindOS[it.Kind] != s.GOOS || (it.Kind == "apt" && !s.Has("dpkg-query")) || (it.Kind == "dnf" && !s.Has("dnf")) {
		r.Status, r.Detail = Unsupported, fmt.Sprintf("%s packages can't be installed on this device", it.Kind)
		return r
	}
	if it.Action == "remove" && it.Kind == "pkg" {
		r.Status, r.Detail = Unsupported, "macOS packages have no uninstaller; remove it with a script"
		return r
	}
	have, err := s.Present(ctx, it)
	if err != nil {
		r.Status, r.Detail = Failed, err.Error()
		return r
	}
	want := it.Action == "install"
	if have == want {
		r.Status = map[bool]string{true: Installed, false: Absent}[have]
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, InstallTimeout)
	defer cancel()
	if want {
		err = s.install(ctx, it)
	} else {
		err = s.remove(ctx, it)
	}
	if err != nil {
		r.Status, r.Detail = Failed, err.Error()
		return r
	}
	// Check the installer did what it said.
	if have, err = s.Present(context.Background(), it); err == nil && have != want {
		r.Status = Failed
		r.Detail = map[bool]string{true: "the installer finished but the app isn't detected (check the reference)", false: "the uninstaller finished but the app is still detected"}[want]
		return r
	}
	r.Status = map[bool]string{true: Installed, false: Absent}[want]
	r.Detail = map[bool]string{true: "installed by Nexus", false: "removed by Nexus"}[want]
	return r
}

// Manager reconciles a whole list, one item at a time, and doesn't retry a failed item for
// RetryAfter unless the item changed.
type Manager struct {
	Sys Sys

	mu     sync.Mutex
	failed map[string]failure
}

type failure struct {
	at  time.Time
	res Result
}

func key(it Item) string {
	return strings.Join(append([]string{it.ID, it.Action, it.Kind, it.Ref, it.URL, it.SHA256}, it.Args...), "\x00")
}

// Apply reconciles every item and returns their results, in the policy's order.
func (m *Manager) Apply(ctx context.Context, items []Item) []Result {
	now := time.Now
	if m.Sys.Now != nil {
		now = m.Sys.Now
	}
	m.mu.Lock()
	if m.failed == nil {
		m.failed = map[string]failure{}
	}
	m.mu.Unlock()
	out := make([]Result, 0, len(items))
	keep := map[string]bool{}
	for _, it := range items {
		k := key(it)
		keep[k] = true
		m.mu.Lock()
		f, ok := m.failed[k]
		m.mu.Unlock()
		if ok && now().Sub(f.at) < RetryAfter {
			out = append(out, f.res)
			continue
		}
		r := m.Sys.Reconcile(ctx, it)
		m.mu.Lock()
		if r.Status == Failed {
			m.failed[k] = failure{at: now(), res: r}
		} else {
			delete(m.failed, k)
		}
		m.mu.Unlock()
		out = append(out, r)
	}
	m.mu.Lock()
	for k := range m.failed {
		if !keep[k] {
			delete(m.failed, k)
		}
	}
	m.mu.Unlock()
	return out
}

// MaxDownload caps an installer download.
const MaxDownload = 4 << 30

// Download fetches an installer over HTTPS into dir and checks its SHA-256.
func Download(ctx context.Context, rawURL, want, dir string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return "", errors.New("the installer URL must be https")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 5 {
			return errors.New("redirected away from https")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	ext := strings.ToLower(filepath.Ext(u.Path))
	if ext != ".msi" && ext != ".pkg" {
		ext = ""
	}
	f, err := os.CreateTemp(dir, "installer-*"+ext)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, MaxDownload+1))
	f.Close()
	if err == nil && n > MaxDownload {
		err = errors.New("download: larger than 4 GB")
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != strings.ToLower(want) {
		err = errors.New("download: SHA-256 doesn't match; not installing it")
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// FindWinget finds winget.exe for the SYSTEM account (it lives in the App Installer package).
func FindWinget(lookPath func(string) (string, error)) string {
	for _, arch := range []string{"x64", "arm64"} {
		m, _ := filepath.Glob(`C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_` + arch + `__8wekyb3d8bbwe\winget.exe`)
		if len(m) > 0 {
			sort.Strings(m)
			return m[len(m)-1]
		}
	}
	if p, err := lookPath("winget"); err == nil {
		return p
	}
	return ""
}

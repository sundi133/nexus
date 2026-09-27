// Package settings makes the device match the organization's device policies where the
// organization asked Nexus to fix them, not just report them: firewall on, a screen-lock
// timeout, disk encryption (BitLocker), and escrow of BitLocker recovery keys. Settings arrive
// in the signed policy with block rules. The agent re-asserts them hourly, so a setting someone
// turns off comes back, and reports per setting what it found and did.
//
// It's conservative by design. Anything an OS allows only through MDM or the signed-in user
// (FileVault, the macOS screen lock, LUKS) is reported as unsupported, with what to do instead.
package settings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Desired is what the organization wants enforced (absent or zero: leave alone).
type Desired struct {
	Firewall           bool `json:"firewall,omitempty"`
	ScreenLockMinutes  int  `json:"screen_lock_minutes,omitempty"` // lock after this much inactivity
	DiskEncryption     bool `json:"disk_encryption,omitempty"`
	EscrowRecoveryKeys bool `json:"escrow_recovery_keys,omitempty"`
}

// Empty reports whether nothing is to be managed.
func (d Desired) Empty() bool { return d == Desired{} }

// Result statuses.
const (
	Compliant      = "compliant"       // already as wanted
	Applied        = "applied"         // changed now
	PendingRestart = "pending_restart" // changed; takes effect after a restart or sign-in
	Failed         = "failed"
	Unsupported    = "unsupported" // this OS can't do it without MDM or the user
)

// Result is one setting's outcome, reported on the next check-in.
type Result struct {
	Key    string `json:"key"` // firewall | screen_lock | disk_encryption
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// RecoveryKey is a disk-encryption recovery key to escrow with the server.
type RecoveryKey struct {
	Volume   string `json:"volume"`
	ID       string `json:"id"`
	Password string `json:"password"`
}

// Sys is what applying settings needs from the operating system (faked in tests).
type Sys interface {
	Run(name string, args ...string) (string, error)
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte) error
	MkdirAll(path string) error
	LookPath(name string) bool
	IsRoot() bool
}

// Outcome of one pass.
type Outcome struct {
	Results      []Result
	RecoveryKeys []RecoveryKey
}

// Apply makes the device match d on this OS.
func Apply(sys Sys, goos string, d Desired) Outcome {
	var o Outcome
	if d.Empty() {
		return o
	}
	if !sys.IsRoot() {
		for _, k := range wanted(goos, d) {
			o.Results = append(o.Results, Result{Key: k, Status: Failed, Detail: "the agent must run as root / SYSTEM to change settings"})
		}
		return o
	}
	switch goos {
	case "darwin":
		o = applyDarwin(sys, d)
	case "windows":
		o = applyWindows(sys, d)
	case "linux":
		o = applyLinux(sys, d)
	default:
		for _, k := range wanted(goos, d) {
			o.Results = append(o.Results, Result{Key: k, Status: Unsupported, Detail: goos + " isn't supported"})
		}
	}
	sort.Slice(o.Results, func(i, j int) bool { return o.Results[i].Key < o.Results[j].Key })
	return o
}

func wanted(goos string, d Desired) []string {
	var k []string
	if d.DiskEncryption || (d.EscrowRecoveryKeys && goos == "windows") {
		k = append(k, "disk_encryption")
	}
	if d.Firewall {
		k = append(k, "firewall")
	}
	if d.ScreenLockMinutes > 0 {
		k = append(k, "screen_lock")
	}
	return k
}

// KeysDigest identifies a set of recovery keys, so unchanged keys aren't sent again.
func KeysDigest(keys []RecoveryKey) string {
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k.Volume + "\x00" + k.ID + "\x00" + k.Password + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---- Parsers (shared, so every platform's logic is tested everywhere) -------------------------

var (
	bdeProtectionOn = regexp.MustCompile(`(?mi)^\s*Protection Status:\s*Protection On`)
	bdeKeyID        = regexp.MustCompile(`(?m)^\s*ID:\s*(\{[0-9A-Fa-f-]{36}\})`)
	bdePassword     = regexp.MustCompile(`(?m)^\s*(\d{6}(?:-\d{6}){7})\s*$`)
)

// ParseBitLockerOn reads `manage-bde -status C:`.
func ParseBitLockerOn(out string) bool { return bdeProtectionOn.MatchString(out) }

// ParseRecoveryPasswords reads `manage-bde -protectors -get C: -Type RecoveryPassword`: each
// protector is an "ID: {…}" line followed by "Password:" and the 48-digit password.
func ParseRecoveryPasswords(volume, out string) []RecoveryKey {
	var keys []RecoveryKey
	ids := bdeKeyID.FindAllStringSubmatchIndex(out, -1)
	for i, m := range ids {
		end := len(out)
		if i+1 < len(ids) {
			end = ids[i+1][0]
		}
		if p := bdePassword.FindStringSubmatch(out[m[1]:end]); p != nil {
			keys = append(keys, RecoveryKey{Volume: volume, ID: out[m[2]:m[3]], Password: p[1]})
		}
	}
	return keys
}

// ParseTPMReady reads `(Get-Tpm).TpmReady` (PowerShell prints True/False).
func ParseTPMReady(out string) bool { return strings.EqualFold(strings.TrimSpace(out), "true") }

// ---- Running commands ------------------------------------------------------------------------

// OS is the real Sys.
type OS struct{ Root bool }

func (OS) Run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
func (OS) LookPath(name string) bool { _, err := exec.LookPath(name); return err == nil }
func (o OS) IsRoot() bool            { return o.Root }

// firstLine keeps error details short in reports.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func failed(key, what string, out string, err error) Result {
	d := what
	if l := firstLine(out); l != "" {
		d += ": " + l
	} else if err != nil {
		d += ": " + err.Error()
	}
	return Result{Key: key, Status: Failed, Detail: d}
}

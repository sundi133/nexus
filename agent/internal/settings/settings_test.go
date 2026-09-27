package settings

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeSys answers commands from a table (first matching prefix wins) and records them in order.
type fakeSys struct {
	root    bool
	paths   map[string]bool
	answers []answer
	files   map[string]string
	ran     []string
}

type answer struct {
	prefix string
	out    string
	err    error
}

func (f *fakeSys) Run(name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.ran = append(f.ran, cmd)
	for _, a := range f.answers {
		if strings.HasPrefix(cmd, a.prefix) {
			return a.out, a.err
		}
	}
	return "", nil
}
func (f *fakeSys) ReadFile(p string) ([]byte, error) {
	if c, ok := f.files[p]; ok {
		return []byte(c), nil
	}
	return nil, os.ErrNotExist
}
func (f *fakeSys) WriteFile(p string, d []byte) error { f.files[p] = string(d); return nil }
func (f *fakeSys) MkdirAll(string) error              { return nil }
func (f *fakeSys) LookPath(n string) bool             { return f.paths[n] }
func (f *fakeSys) IsRoot() bool                       { return f.root }

func newSys(paths ...string) *fakeSys {
	f := &fakeSys{root: true, paths: map[string]bool{}, files: map[string]string{}}
	for _, p := range paths {
		f.paths[p] = true
	}
	return f
}

func (f *fakeSys) on(prefix, out string, err error) *fakeSys {
	f.answers = append(f.answers, answer{prefix, out, err})
	return f
}

func (f *fakeSys) ranIndex(t *testing.T, cmd string) int {
	t.Helper()
	for i, c := range f.ran {
		if c == cmd {
			return i
		}
	}
	t.Fatalf("didn't run %q; ran %q", cmd, f.ran)
	return -1
}

func result(t *testing.T, o Outcome, key string) Result {
	t.Helper()
	for _, r := range o.Results {
		if r.Key == key {
			return r
		}
	}
	t.Fatalf("no result for %s in %+v", key, o.Results)
	return Result{}
}

const protectors = `BitLocker Drive Encryption: Configuration Tool version 10.0.22621
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

Volume C: [Windows]
All Key Protectors

    Numerical Password:
      ID: {4B8E2E5C-6A2B-4B6F-9B3D-1E2F3A4B5C6D}
      Password:
        123456-234567-345678-456789-567890-678901-789012-890123

    Numerical Password:
      ID: {00000000-1111-2222-3333-444444444444}
      Password:
        111111-222222-333333-444444-555555-666666-777777-888888
`

func TestParseRecoveryPasswords(t *testing.T) {
	keys := ParseRecoveryPasswords("C:", protectors)
	if len(keys) != 2 || keys[0].ID != "{4B8E2E5C-6A2B-4B6F-9B3D-1E2F3A4B5C6D}" || keys[0].Password != "123456-234567-345678-456789-567890-678901-789012-890123" || keys[1].Password[:6] != "111111" {
		t.Fatalf("keys = %+v", keys)
	}
	if len(ParseRecoveryPasswords("C:", "ERROR: No key protectors found.")) != 0 {
		t.Fatal("parsed keys from nothing")
	}
	if KeysDigest(keys) == KeysDigest(keys[:1]) {
		t.Fatal("digest ignores a key")
	}
}

func TestNothingWithoutRoot(t *testing.T) {
	f := newSys()
	f.root = false
	o := Apply(f, "linux", Desired{Firewall: true})
	if r := result(t, o, "firewall"); r.Status != Failed || len(f.ran) != 0 {
		t.Fatalf("%+v ran %q", r, f.ran)
	}
	if o := Apply(newSys(), "linux", Desired{}); len(o.Results) != 0 {
		t.Fatalf("empty policy did something: %+v", o)
	}
}

func TestWindowsFirewallAndScreenLock(t *testing.T) {
	f := newSys().
		on("netsh advfirewall show", "Domain Profile Settings:\nState OFF\nPrivate Profile Settings:\nState ON\nPublic Profile Settings:\nState ON", nil).
		on("reg query", `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    InactivityTimeoutSecs    REG_DWORD    1800`, nil)
	o := Apply(f, "windows", Desired{Firewall: true, ScreenLockMinutes: 10})
	if r := result(t, o, "firewall"); r.Status != Applied {
		t.Fatalf("firewall %+v", r)
	}
	f.ranIndex(t, "netsh advfirewall set allprofiles state on")
	if r := result(t, o, "screen_lock"); r.Status != PendingRestart { // 30 min is longer than 10: tightened
		t.Fatalf("screen lock %+v", r)
	}
	f.ranIndex(t, `reg add `+policiesSystem+` /v InactivityTimeoutSecs /t REG_DWORD /d 600 /f`)

	g := newSys().
		on("netsh advfirewall show", "State ON\nState ON\nState ON", nil).
		on("reg query", "    InactivityTimeoutSecs    REG_DWORD    300", nil)
	o = Apply(g, "windows", Desired{Firewall: true, ScreenLockMinutes: 10})
	if result(t, o, "firewall").Status != Compliant || result(t, o, "screen_lock").Status != Compliant {
		t.Fatalf("%+v", o.Results)
	}
	for _, c := range g.ran {
		if strings.Contains(c, " set ") || strings.HasPrefix(c, "reg add") {
			t.Fatalf("changed a compliant device: %q", c)
		}
	}
}

func TestWindowsBitLocker(t *testing.T) {
	// On, with recovery passwords: compliant, keys escrowed.
	f := newSys().on("manage-bde -status", "Protection Status:    Protection On", nil).on("manage-bde -protectors -get", protectors, nil)
	o := Apply(f, "windows", Desired{DiskEncryption: true, EscrowRecoveryKeys: true})
	if result(t, o, "disk_encryption").Status != Compliant || len(o.RecoveryKeys) != 2 {
		t.Fatalf("%+v", o)
	}
	// Escrow off: keys stay on the device.
	if o := Apply(f, "windows", Desired{DiskEncryption: true}); len(o.RecoveryKeys) != 0 {
		t.Fatal("sent keys without escrow")
	}

	// Off, TPM ready: a recovery password first, then the TPM, then encryption.
	g := newSys().
		on("manage-bde -status", "Protection Status:    Protection Off", nil).
		on("powershell", "True", nil).
		on("manage-bde -protectors -get", "ERROR: No key protectors found.", nil)
	o = Apply(g, "windows", Desired{DiskEncryption: true, EscrowRecoveryKeys: true})
	if r := result(t, o, "disk_encryption"); r.Status != Applied {
		t.Fatalf("%+v", r)
	}
	pw, tpm, on := g.ranIndex(t, "manage-bde -protectors -add C: -RecoveryPassword"), g.ranIndex(t, "manage-bde -protectors -add C: -TPM"), g.ranIndex(t, "manage-bde -on C: -UsedSpaceOnly -SkipHardwareTest")
	if !(pw < tpm && tpm < on) {
		t.Fatalf("order: %q", g.ran)
	}

	// Off, no TPM: left alone.
	h := newSys().on("manage-bde -status", "Protection Status:    Protection Off", nil).on("powershell", "False", nil)
	if r := result(t, Apply(h, "windows", Desired{DiskEncryption: true}), "disk_encryption"); r.Status != Unsupported {
		t.Fatalf("%+v", r)
	}
	for _, c := range h.ran {
		if strings.Contains(c, "-add") || strings.Contains(c, " -on ") {
			t.Fatalf("changed a device without a TPM: %q", c)
		}
	}

	// On, TPM only, escrow wanted: a recovery password is added so there's something to escrow.
	k := newSys().on("manage-bde -status", "Protection Status:    Protection On", nil)
	k.answers = append(k.answers, answer{prefix: "manage-bde -protectors -add C: -RecoveryPassword"})
	k.on("manage-bde -protectors -get", "", nil)
	o = Apply(k, "windows", Desired{EscrowRecoveryKeys: true})
	k.ranIndex(t, "manage-bde -protectors -add C: -RecoveryPassword")
	if r := result(t, o, "disk_encryption"); r.Status != Compliant || r.Detail != "recovery password added for escrow" {
		t.Fatalf("%+v", r)
	}
}

func TestLinuxFirewallNeverLocksOutSSH(t *testing.T) {
	f := newSys("ufw", "sshd").on("ufw status", "Status: inactive", nil)
	o := Apply(f, "linux", Desired{Firewall: true})
	if r := result(t, o, "firewall"); r.Status != Applied || !strings.Contains(r.Detail, "SSH allowed") {
		t.Fatalf("%+v", r)
	}
	if f.ranIndex(t, "ufw allow OpenSSH") > f.ranIndex(t, "ufw --force enable") {
		t.Fatal("enabled ufw before allowing SSH")
	}
	// If SSH can't be allowed, the firewall stays off.
	g := newSys("ufw", "sshd").on("ufw status", "Status: inactive", nil).on("ufw allow", "ERROR", errors.New("exit 1"))
	if r := result(t, Apply(g, "linux", Desired{Firewall: true}), "firewall"); r.Status != Failed {
		t.Fatalf("%+v", r)
	}
	for _, c := range g.ran {
		if c == "ufw --force enable" {
			t.Fatal("enabled ufw without SSH")
		}
	}
	// Already active: untouched. firewalld: started. Neither: unsupported.
	if r := result(t, Apply(newSys("ufw").on("ufw status", "Status: active", nil), "linux", Desired{Firewall: true}), "firewall"); r.Status != Compliant {
		t.Fatalf("%+v", r)
	}
	h := newSys("firewall-cmd").on("firewall-cmd --state", "not running", errors.New("exit 252"))
	if r := result(t, Apply(h, "linux", Desired{Firewall: true}), "firewall"); r.Status != Applied {
		t.Fatalf("%+v", r)
	}
	h.ranIndex(t, "systemctl enable --now firewalld")
	if r := result(t, Apply(newSys(), "linux", Desired{Firewall: true}), "firewall"); r.Status != Unsupported {
		t.Fatalf("%+v", r)
	}
}

func TestLinuxScreenLock(t *testing.T) {
	f := newSys("dconf")
	f.files[dconfProfile] = "user-db:user\nsystem-db:site\n" // someone else's system database: kept
	o := Apply(f, "linux", Desired{ScreenLockMinutes: 5})
	if r := result(t, o, "screen_lock"); r.Status != PendingRestart {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(f.files[dconfFile], "idle-delay=uint32 300") || !strings.Contains(f.files[dconfLocks], "/org/gnome/desktop/screensaver/lock-enabled") {
		t.Fatalf("files = %v", f.files)
	}
	if p := f.files[dconfProfile]; !strings.Contains(p, "system-db:site") || !strings.Contains(p, "system-db:local") {
		t.Fatalf("profile = %q", p)
	}
	f.ranIndex(t, "dconf update")
	f.ran = nil
	if r := result(t, Apply(f, "linux", Desired{ScreenLockMinutes: 5}), "screen_lock"); r.Status != Compliant || len(f.ran) != 0 {
		t.Fatalf("second pass %+v ran %q", r, f.ran)
	}
	if r := result(t, Apply(f, "linux", Desired{ScreenLockMinutes: 15}), "screen_lock"); r.Status != PendingRestart || !strings.Contains(f.files[dconfFile], "uint32 900") {
		t.Fatalf("change %+v", r)
	}
	if r := result(t, Apply(newSys(), "linux", Desired{ScreenLockMinutes: 5}), "screen_lock"); r.Status != Unsupported {
		t.Fatalf("server %+v", r)
	}
}

func TestMacOS(t *testing.T) {
	f := newSys().on(socketfilterfw+" --getglobalstate", "Firewall is disabled. (State = 0)", nil)
	o := Apply(f, "darwin", Desired{Firewall: true, ScreenLockMinutes: 5, DiskEncryption: true})
	if result(t, o, "firewall").Status != Applied {
		t.Fatalf("%+v", o.Results)
	}
	f.ranIndex(t, socketfilterfw+" --setglobalstate on")
	if result(t, o, "screen_lock").Status != Unsupported || result(t, o, "disk_encryption").Status != Unsupported {
		t.Fatalf("%+v", o.Results)
	}
	g := newSys().on(socketfilterfw+" --getglobalstate", "Firewall is enabled. (State = 1)", nil)
	if result(t, Apply(g, "darwin", Desired{Firewall: true}), "firewall").Status != Compliant {
		t.Fatal("enabled firewall not compliant")
	}
	// Escrow is on by default and only means something for BitLocker: Macs and Linux say nothing.
	for _, goos := range []string{"darwin", "linux"} {
		if o := Apply(newSys(), goos, Desired{EscrowRecoveryKeys: true}); len(o.Results) != 0 {
			t.Fatalf("%s reported %+v", goos, o.Results)
		}
	}
}

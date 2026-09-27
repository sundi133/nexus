// Package accounts gives people a local account on their laptop with their company password
// (like JumpCloud's user binding and password sync). The signed device policy says who gets an
// account (and whether it's an admin, or disabled because they left); passwords arrive separately,
// encrypted to this device's key and signed by the organization, whenever the person signs in to
// Nexus or changes their password. Passwords are set from stdin, never on a command line, and
// are only ever held in memory.
package accounts

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Account is one person's account, from the policy.
type Account struct {
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	FullName        string `json:"full_name"`
	Admin           bool   `json:"admin"`
	State           string `json:"state"`     // active | disabled
	TakeOver        bool   `json:"take_over"` // manage a local account that already exists
	PasswordVersion int    `json:"password_version"`
}

// Status is what the agent reports for an account.
type Status struct {
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	Status          string `json:"status"` // active | waiting_password | disabled | failed
	PasswordVersion int    `json:"password_version"`
	Detail          string `json:"detail,omitempty"`
}

// Sys runs commands; stdin carries anything secret (faked in tests).
type Sys struct {
	GOOS string
	Run  func(ctx context.Context, stdin, name string, args ...string) (string, error)
}

var nameOK = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,19}$`)

// Never managed, whatever the policy says.
var reserved = map[string]bool{
	"root": true, "admin": true, "administrator": true, "guest": true, "daemon": true, "nobody": true, "bin": true, "sys": true, "sync": true,
	"defaultaccount": true, "wdagutilityaccount": true, "nexus": true, "sshd": true, "www-data": true, "messagebus": true, "operator": true, "games": true, "mail": true,
}

func validName(n string) error {
	if !nameOK.MatchString(n) || strings.HasSuffix(n, ".") {
		return fmt.Errorf("%q isn't a valid account name", n)
	}
	if reserved[n] || strings.HasPrefix(n, "systemd-") {
		return fmt.Errorf("%q is a system account and can't be managed", n)
	}
	return nil
}

type record struct {
	UserID  string `json:"user_id"`
	Version int    `json:"version"`
	Created bool   `json:"created"` // Nexus made it (so it's locked until it has a password)
	Removed bool   `json:"removed,omitempty"`
}

type pending struct {
	version int
	secret  Secret
}

// Manager keeps the accounts Nexus manages on this device.
type Manager struct {
	Sys      Sys
	StateDir string
	DeviceID string
	Key      *ecdh.PrivateKey

	mu      sync.Mutex
	secrets map[string]pending // user ID → the newest password received, not yet set
}

func (m *Manager) statePath() string { return filepath.Join(m.StateDir, "accounts.json") }

func (m *Manager) load() map[string]*record {
	out := map[string]*record{}
	if raw, err := os.ReadFile(m.statePath()); err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func (m *Manager) save(recs map[string]*record) {
	if raw, err := json.Marshal(recs); err == nil {
		_ = os.WriteFile(m.statePath(), raw, 0o600)
	}
}

// Offer takes a password the server sent (already verified as signed for this device) and keeps
// it in memory until the next Apply. It returns false when it's nothing new.
func (m *Manager) Offer(userID string, version int, ct string) (bool, error) {
	s, err := Open(m.Key, m.DeviceID, userID, version, ct)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.secrets == nil {
		m.secrets = map[string]pending{}
	}
	if cur, ok := m.secrets[userID]; ok && cur.version >= version {
		return false, nil
	}
	m.secrets[userID] = pending{version: version, secret: s}
	return true, nil
}

func (m *Manager) take(userID string, applied int) (pending, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.secrets[userID]
	if !ok || p.version <= applied {
		delete(m.secrets, userID)
		return pending{}, false
	}
	return p, true
}

func (m *Manager) forget(userID string, version int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.secrets[userID]; ok && p.version <= version {
		delete(m.secrets, userID)
	}
}

// Apply makes the device's accounts match the policy and says where each stands.
func (m *Manager) Apply(ctx context.Context, want []Account) []Status {
	recs := m.load()
	out := make([]Status, 0, len(want))
	seen := map[string]bool{}
	for _, a := range want {
		seen[a.Username] = true
		st := m.apply(ctx, recs, a)
		out = append(out, st)
	}
	// Accounts Nexus manages that the policy no longer lists: disabled, never deleted (their files stay).
	for name, r := range recs {
		if seen[name] || r.Removed {
			continue
		}
		if err := m.Sys.setEnabled(ctx, name, false); err == nil {
			r.Removed = true
		}
	}
	m.save(recs)
	return out
}

func (m *Manager) apply(ctx context.Context, recs map[string]*record, a Account) Status {
	st := Status{UserID: a.UserID, Username: a.Username}
	fail := func(format string, args ...any) Status {
		st.Status, st.Detail = "failed", fmt.Sprintf(format, args...)
		return st
	}
	if err := validName(a.Username); err != nil {
		return fail("%v", err)
	}
	r := recs[a.Username]
	if r != nil && r.UserID != a.UserID {
		return fail("the account %s belongs to someone else in Nexus", a.Username)
	}
	exists, err := m.Sys.exists(ctx, a.Username)
	if err != nil {
		return fail("couldn't look up the account: %v", err)
	}
	switch {
	case !exists && a.State == "disabled":
		st.Status = "disabled"
		if r != nil {
			delete(recs, a.Username) // it was deleted by hand: nothing left to manage
		}
		return st
	case !exists:
		if err := m.Sys.create(ctx, a.Username, a.FullName); err != nil {
			return fail("couldn't create the account: %v", err)
		}
		r = &record{UserID: a.UserID, Created: true}
		recs[a.Username] = r
	case r == nil && !a.TakeOver:
		return fail("a local account named %s already exists; turn on take over to manage it", a.Username)
	case r == nil:
		r = &record{UserID: a.UserID}
		recs[a.Username] = r
	}
	r.Removed = false
	st.PasswordVersion = r.Version

	if p, ok := m.take(a.UserID, r.Version); ok && a.State != "disabled" {
		if err := m.Sys.setPassword(ctx, a.Username, p.secret); err != nil {
			return fail("couldn't set the password: %v", err)
		}
		r.Version = p.version
		st.PasswordVersion = p.version
		m.forget(a.UserID, p.version)
	}
	if isAdmin, err := m.Sys.isAdmin(ctx, a.Username); err != nil {
		return fail("couldn't read admin rights: %v", err)
	} else if isAdmin != a.Admin {
		if err := m.Sys.setAdmin(ctx, a.Username, a.Admin); err != nil {
			return fail("couldn't change admin rights: %v", err)
		}
	}
	switch {
	case a.State == "disabled":
		if err := m.Sys.setEnabled(ctx, a.Username, false); err != nil {
			return fail("couldn't disable the account: %v", err)
		}
		st.Status = "disabled"
	case r.Created && r.Version == 0:
		// Created by Nexus but no password yet: stays locked until the person signs in to Nexus.
		if err := m.Sys.setEnabled(ctx, a.Username, false); err != nil {
			return fail("couldn't lock the account: %v", err)
		}
		st.Status, st.Detail = "waiting_password", "sign in to Nexus once to set the password"
	default:
		if err := m.Sys.setEnabled(ctx, a.Username, true); err != nil {
			return fail("couldn't enable the account: %v", err)
		}
		st.Status = "active"
		if r.Version == 0 {
			st.Detail = "keeps its own password until the person signs in to Nexus"
		}
	}
	return st
}

// ---- Per-OS operations ------------------------------------------------------------------------

var errUnsupported = errors.New("local accounts aren't supported on this OS")

func (s Sys) run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	out, err := s.Run(ctx, stdin, name, args...)
	if err != nil {
		msg := strings.TrimSpace(out)
		if i := strings.LastIndexByte(msg, '\n'); i >= 0 {
			msg = msg[i+1:]
		}
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return out, errors.New(msg)
	}
	return out, nil
}

// ps runs a PowerShell script with its input as JSON on stdin (as $i).
func (s Sys) ps(ctx context.Context, in map[string]string, script string) (string, error) {
	raw, _ := json.Marshal(in)
	return s.run(ctx, string(raw), "powershell", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference = 'Stop'; $i = [Console]::In.ReadToEnd() | ConvertFrom-Json; "+script)
}

func (s Sys) linuxAdminGroup(ctx context.Context) string {
	if _, err := s.Run(ctx, "", "getent", "group", "sudo"); err == nil {
		return "sudo"
	}
	return "wheel"
}

func (s Sys) exists(ctx context.Context, u string) (bool, error) {
	switch s.GOOS {
	case "linux":
		_, err := s.Run(ctx, "", "id", "-u", u)
		return err == nil, nil
	case "darwin":
		_, err := s.Run(ctx, "", "dscl", ".", "-read", "/Users/"+u, "UniqueID")
		return err == nil, nil
	case "windows":
		out, err := s.ps(ctx, map[string]string{"user": u}, "if (Get-LocalUser -Name $i.user -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }")
		return strings.TrimSpace(out) == "yes", err
	}
	return false, errUnsupported
}

func randomPassword() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b) + "aA1!"
}

func (s Sys) create(ctx context.Context, u, full string) error {
	switch s.GOOS {
	case "linux":
		_, err := s.run(ctx, "", "useradd", "-m", "-s", "/bin/bash", "-c", full, u)
		return err
	case "darwin":
		// A throwaway password (it's locked right after); the real one arrives from Nexus.
		_, err := s.run(ctx, "", "sysadminctl", "-addUser", u, "-fullName", full, "-password", randomPassword())
		return err
	case "windows":
		_, err := s.ps(ctx, map[string]string{"user": u, "full": full}, "New-LocalUser -Name $i.user -FullName $i.full -NoPassword -AccountNeverExpires | Out-Null")
		return err
	}
	return errUnsupported
}

// jxaPassword sets a macOS password through OpenDirectory, reading it from stdin. With the old
// password it's a change (the login keychain and FileVault follow); without, a reset.
const jxaPassword = `ObjC.import('OpenDirectory');
const d = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
const i = JSON.parse($.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding).js);
const node = $.ODNode.nodeWithSessionTypeError($.ODSession.defaultSession, $.kODNodeTypeLocalNodes, null);
const rec = node.recordWithRecordTypeNameAttributesError($.kODRecordTypeUsers, i.user, null, null);
if (!rec || rec.isNil()) { throw new Error('no such account'); }
let ok = false;
if (i.old) { ok = rec.changePasswordToPasswordError(i.old, i.new, null); }
if (!ok) { ok = rec.setPasswordError(i.new, null); }
if (!ok) { throw new Error('OpenDirectory refused the password'); }
'ok';`

func (s Sys) setPassword(ctx context.Context, u string, sec Secret) error {
	switch s.GOOS {
	case "linux":
		if strings.ContainsAny(u+sec.Password, ":\n") {
			return errors.New("the password can't contain a newline or colon on Linux")
		}
		_, err := s.run(ctx, u+":"+sec.Password+"\n", "chpasswd")
		return err
	case "darwin":
		raw, _ := json.Marshal(map[string]string{"user": u, "new": sec.Password, "old": sec.Old})
		_, err := s.run(ctx, string(raw), "osascript", "-l", "JavaScript", "-e", jxaPassword)
		return err
	case "windows":
		_, err := s.ps(ctx, map[string]string{"user": u, "new": sec.Password}, "Set-LocalUser -Name $i.user -Password (ConvertTo-SecureString $i.new -AsPlainText -Force) -PasswordNeverExpires $true")
		return err
	}
	return errUnsupported
}

func (s Sys) isAdmin(ctx context.Context, u string) (bool, error) {
	switch s.GOOS {
	case "linux":
		out, err := s.run(ctx, "", "id", "-nG", u)
		if err != nil {
			return false, err
		}
		g := s.linuxAdminGroup(ctx)
		for _, x := range strings.Fields(out) {
			if x == g {
				return true, nil
			}
		}
		return false, nil
	case "darwin":
		out, _ := s.Run(ctx, "", "dseditgroup", "-o", "checkmember", "-m", u, "admin")
		return strings.HasPrefix(strings.TrimSpace(out), "yes"), nil
	case "windows":
		out, err := s.ps(ctx, map[string]string{"user": u}, `if (Get-LocalGroupMember -SID S-1-5-32-544 | Where-Object { $_.Name -eq "$env:COMPUTERNAME\$($i.user)" }) { 'yes' } else { 'no' }`)
		return strings.TrimSpace(out) == "yes", err
	}
	return false, errUnsupported
}

func (s Sys) setAdmin(ctx context.Context, u string, admin bool) error {
	var err error
	switch s.GOOS {
	case "linux":
		g := s.linuxAdminGroup(ctx)
		if admin {
			_, err = s.run(ctx, "", "usermod", "-aG", g, u)
		} else {
			_, err = s.run(ctx, "", "gpasswd", "-d", u, g)
		}
	case "darwin":
		op := "-d"
		if admin {
			op = "-a"
		}
		_, err = s.run(ctx, "", "dseditgroup", "-o", "edit", op, u, "-t", "user", "admin")
	case "windows":
		cmd := "Remove-LocalGroupMember"
		if admin {
			cmd = "Add-LocalGroupMember"
		}
		_, err = s.ps(ctx, map[string]string{"user": u}, cmd+" -SID S-1-5-32-544 -Member $i.user")
	default:
		err = errUnsupported
	}
	return err
}

func (s Sys) setEnabled(ctx context.Context, u string, on bool) error {
	var err error
	switch s.GOOS {
	case "linux":
		if on {
			if _, err = s.run(ctx, "", "usermod", "-U", u); err == nil {
				_, err = s.run(ctx, "", "chage", "-E", "-1", u)
			}
		} else {
			_, err = s.run(ctx, "", "usermod", "-L", "-e", "1", u)
		}
	case "darwin":
		flag := "-disableuser"
		if on {
			flag = "-enableuser"
		}
		_, err = s.run(ctx, "", "pwpolicy", "-u", u, flag)
	case "windows":
		cmd := "Disable-LocalUser"
		if on {
			cmd = "Enable-LocalUser"
		}
		_, err = s.ps(ctx, map[string]string{"user": u}, cmd+" -Name $i.user")
	default:
		err = errUnsupported
	}
	return err
}

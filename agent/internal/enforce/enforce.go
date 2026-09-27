// Package enforce applies the organization's block rules on this device:
// app rules terminate matching programs (a watcher checks about every 2
// seconds), domain rules sinkhole domains in a Nexus-managed section of the
// hosts file. Rules arrive as a policy signed with the organization's command
// key; the agent refuses anything unsigned, for another device, or older than
// what it already applied. The last policy is kept on disk, so blocking
// continues across restarts and while offline.
package enforce

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/votal-ai/nexus/agent/internal/accounts"
	"github.com/votal-ai/nexus/agent/internal/command"
	"github.com/votal-ai/nexus/agent/internal/settings"
	"github.com/votal-ai/nexus/agent/internal/software"
)

const policyTyp = "nexus-policy+jwt"

type Rule struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Kind  string `json:"kind"`  // app | domain
	Match string `json:"match"` // name | path | sha256 | domain
	Value string `json:"value"`
	Mode  string `json:"mode"` // monitor | block
}

type Policy struct {
	Device   string             `json:"sub"`
	TS       int64              `json:"ts"`
	Ver      string             `json:"ver"`
	Rules    []Rule             `json:"rules"`
	Settings settings.Desired   `json:"settings"` // device settings to enforce (firewall, screen lock, BitLocker)
	Software []software.Item    `json:"software"` // apps to install or remove
	Accounts []accounts.Account `json:"accounts"` // people's local accounts
}

// Event is reported on the next check-in; repeats are counted, not repeated.
type Event struct {
	RuleID  string `json:"rule_id"`
	Action  string `json:"action"` // terminated | would_terminate | failed
	Subject string `json:"subject"`
	User    string `json:"user"`
	Count   int    `json:"count"`
	Detail  string `json:"detail,omitempty"`
	At      string `json:"at"`
}

type Report struct {
	Version      string                 `json:"version"`
	Status       string                 `json:"status"`
	Events       []Event                `json:"events"`
	Settings     []settings.Result      `json:"settings"`
	RecoveryKeys []settings.RecoveryKey `json:"recovery_keys,omitempty"` // only when they changed
	Software     []software.Result      `json:"software"`                // null until the first pass
	Accounts     []accounts.Status      `json:"accounts"`                // null until the first pass
}

// Proc is a running process.
type Proc struct {
	PID  int
	Path string
	User string
}

// Enforcer holds the current policy and applies it.
type Enforcer struct {
	StateDir  string
	DeviceID  string
	Key       func() (ed25519.PublicKey, error)
	OwnHost   string // the Nexus server: never blocked
	HostsPath string
	Log       *slog.Logger
	// Replaceable in tests.
	Processes func() ([]Proc, error)
	Kill      func(pid int) error
	FlushDNS  func()
	Now       func() time.Time
	// ApplySettings makes the device match the policy's settings (settings.Apply on this OS).
	ApplySettings func(settings.Desired) settings.Outcome
	// ApplySoftware installs and removes the policy's apps (software.Manager.Apply).
	ApplySoftware func([]software.Item) []software.Result
	// ApplyAccounts makes people's local accounts match the policy (accounts.Manager.Apply);
	// OfferPassword hands it a password the server sent (accounts.Manager.Offer).
	ApplyAccounts func([]accounts.Account) []accounts.Status
	OfferPassword func(userID string, version int, ct string) (bool, error)

	mu        sync.Mutex
	monitored map[string]bool // rule|pid already reported in monitor mode
	policy    *Policy
	status    string
	events    map[string]*Event
	hashes    map[string]hashEntry
	applied   bool

	settingsRunning bool
	settingsAt      time.Time
	settingsRes     []settings.Result
	pendingKeys     []settings.RecoveryKey

	softwareRunning bool
	softwareAt      time.Time
	softwareRes     []software.Result

	accountsRunning bool
	accountsAt      time.Time
	accountsRes     []accounts.Status
	accountsAgain   bool // a password arrived during a pass: run another
}

// SettingsEvery is how often settings are re-asserted, so ones someone turned off come back.
const SettingsEvery = time.Hour

type hashEntry struct {
	size, mod int64
	sum       string
}

func (e *Enforcer) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}
func (e *Enforcer) statePath() string { return filepath.Join(e.StateDir, "enforcement.json") }

// Load restores the last applied policy (after a restart) and applies it again.
func (e *Enforcer) Load() {
	raw, err := os.ReadFile(e.statePath())
	if err != nil {
		return
	}
	var p Policy
	if json.Unmarshal(raw, &p) != nil || p.Device != e.DeviceID {
		return
	}
	e.mu.Lock()
	e.policy = &p
	e.mu.Unlock()
	e.applyDomains()
	e.settingsSoon()
	e.softwareSoon()
	e.accountsSoon()
}

// Apply verifies a signed policy from a check-in and, when it's new, applies it.
func (e *Enforcer) Apply(jws string) error {
	if jws == "" {
		return nil
	}
	key, err := e.Key()
	if err != nil {
		return err
	}
	payload, err := command.VerifySigned(jws, key, policyTyp, "policy")
	if err != nil {
		return err
	}
	var p Policy
	if err := json.Unmarshal(payload, &p); err != nil {
		return errors.New("malformed policy")
	}
	if p.Device != e.DeviceID {
		return errors.New("policy is for another device")
	}
	e.mu.Lock()
	cur := e.policy
	e.mu.Unlock()
	if cur != nil && p.TS < cur.TS {
		return errors.New("policy is older than the one applied (replayed?)")
	}
	if cur != nil && cur.Ver == p.Ver && e.applied {
		e.mu.Lock()
		e.policy.TS = p.TS
		e.mu.Unlock()
		return nil
	}
	e.mu.Lock()
	e.policy = &p
	e.mu.Unlock()
	if data, err := json.Marshal(p); err == nil {
		_ = os.WriteFile(e.statePath(), data, 0o600)
	}
	e.applyDomains()
	e.Log.Info("block rules applied", "version", p.Ver, "rules", len(p.Rules))
	e.mu.Lock()
	e.settingsAt = time.Time{} // a new policy: apply its settings and apps now
	e.softwareAt = time.Time{}
	e.accountsAt = time.Time{}
	e.mu.Unlock()
	e.settingsSoon()
	e.softwareSoon()
	e.accountsSoon()
	return nil
}

// settingsSoon applies the policy's settings in the background if they're due (new policy,
// startup, or an hour since the last pass). Commands like manage-bde can take a while.
func (e *Enforcer) settingsSoon() {
	e.mu.Lock()
	if e.ApplySettings == nil || e.policy == nil || e.settingsRunning || (!e.settingsAt.IsZero() && e.now().Sub(e.settingsAt) < SettingsEvery) {
		e.mu.Unlock()
		return
	}
	want := e.policy.Settings
	e.settingsRunning = true
	e.mu.Unlock()
	go e.runSettings(want)
}

func (e *Enforcer) runSettings(want settings.Desired) {
	out := e.ApplySettings(want)
	for _, r := range out.Results {
		if r.Status == settings.Applied || r.Status == settings.PendingRestart || r.Status == settings.Failed {
			e.Log.Info("device setting", "key", r.Key, "status", r.Status, "detail", r.Detail)
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.settingsRunning = false
	e.settingsAt = e.now()
	e.settingsRes = out.Results
	if len(out.RecoveryKeys) > 0 && settings.KeysDigest(out.RecoveryKeys) != e.escrowed() {
		e.pendingKeys = out.RecoveryKeys
	}
}

// softwareSoon reconciles the policy's apps in the background when due (new policy, startup, or
// hourly, so an app someone removed comes back). Installs can take many minutes.
func (e *Enforcer) softwareSoon() {
	e.mu.Lock()
	if e.ApplySoftware == nil || e.policy == nil || e.softwareRunning || (!e.softwareAt.IsZero() && e.now().Sub(e.softwareAt) < SettingsEvery) {
		e.mu.Unlock()
		return
	}
	want := append([]software.Item(nil), e.policy.Software...)
	e.softwareRunning = true
	e.mu.Unlock()
	go func() {
		out := e.ApplySoftware(want)
		for _, r := range out {
			if r.Status == software.Failed || strings.HasSuffix(r.Detail, "by Nexus") {
				e.Log.Info("app", "id", r.ID, "status", r.Status, "detail", r.Detail)
			}
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		e.softwareRunning = false
		e.softwareAt = e.now()
		if out == nil {
			out = []software.Result{}
		}
		e.softwareRes = out
	}()
}

const secretTyp = "nexus-secret+jwt"

// OfferPasswords takes the password envelopes from a check-in: each signed by the organization
// for this device, then opened with the device's own key. New ones are applied right away.
func (e *Enforcer) OfferPasswords(jwss []string) {
	if e.OfferPassword == nil || len(jwss) == 0 {
		return
	}
	key, err := e.Key()
	if err != nil {
		return
	}
	fresh := false
	for _, j := range jwss {
		payload, err := command.VerifySigned(j, key, secretTyp, "password")
		if err != nil {
			e.Log.Warn("refused a password", "err", err)
			continue
		}
		var p struct {
			Sub string `json:"sub"`
			UID string `json:"uid"`
			Ver int    `json:"ver"`
			CT  string `json:"ct"`
			Exp int64  `json:"exp"`
		}
		if json.Unmarshal(payload, &p) != nil || p.Sub != e.DeviceID || p.Exp < e.now().Unix() {
			e.Log.Warn("refused a password", "err", "not for this device, or expired")
			continue
		}
		ok, err := e.OfferPassword(p.UID, p.Ver, p.CT)
		if err != nil {
			e.Log.Warn("refused a password", "err", err)
		}
		fresh = fresh || ok
	}
	if fresh {
		e.mu.Lock()
		if e.accountsRunning {
			e.accountsAgain = true
		}
		e.accountsAt = time.Time{}
		e.mu.Unlock()
		e.accountsSoon()
	}
}

// accountsSoon reconciles local accounts in the background when due (new policy or password,
// startup, or hourly, so an account someone re-enabled by hand is disabled again).
func (e *Enforcer) accountsSoon() {
	e.mu.Lock()
	if e.ApplyAccounts == nil || e.policy == nil || e.accountsRunning || (!e.accountsAt.IsZero() && e.now().Sub(e.accountsAt) < SettingsEvery) {
		e.mu.Unlock()
		return
	}
	want := append([]accounts.Account(nil), e.policy.Accounts...)
	e.accountsRunning, e.accountsAgain = true, false
	e.mu.Unlock()
	go func() {
		out := e.ApplyAccounts(want)
		for _, s := range out {
			if s.Status == "failed" {
				e.Log.Warn("local account", "user", s.Username, "detail", s.Detail)
			}
		}
		e.mu.Lock()
		e.accountsRunning = false
		e.accountsAt = e.now()
		if out == nil {
			out = []accounts.Status{}
		}
		e.accountsRes = out
		again := e.accountsAgain
		if again {
			e.accountsAt = time.Time{}
		}
		e.mu.Unlock()
		if again {
			e.accountsSoon()
		}
	}()
}

func (e *Enforcer) settingsBusy() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settingsRunning
}

func (e *Enforcer) escrowPath() string { return filepath.Join(e.StateDir, "escrowed.digest") }

// escrowed is the digest of the recovery keys the server already has.
func (e *Enforcer) escrowed() string {
	b, _ := os.ReadFile(e.escrowPath())
	return strings.TrimSpace(string(b))
}

func (e *Enforcer) rules(kind string) []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policy == nil {
		return nil
	}
	var out []Rule
	for _, r := range e.policy.Rules {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// ---- Domains ----------------------------------------------------------------------------------

const (
	beginMark = "# BEGIN Votal Nexus: managed by your organization; edits here are replaced"
	endMark   = "# END Votal Nexus"
)

func (e *Enforcer) applyDomains() {
	var domains []string
	for _, r := range e.rules("domain") {
		d := strings.ToLower(strings.TrimSpace(r.Value))
		if d == "" || d == strings.ToLower(e.OwnHost) || strings.HasSuffix(strings.ToLower(e.OwnHost), "."+d) || strings.ContainsAny(d, " \t#\r\n") {
			continue
		}
		domains = append(domains, d)
	}
	sort.Strings(domains)
	err := WriteHosts(e.hostsPath(), domains)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applied = err == nil
	nApps, nBlock := 0, 0
	if e.policy != nil {
		for _, r := range e.policy.Rules {
			if r.Kind == "app" {
				nApps++
				if r.Mode == "block" {
					nBlock++
				}
			}
		}
	}
	if err != nil {
		e.status = "couldn't update the hosts file: " + err.Error()
		e.addEvent(Event{Action: "failed", Detail: e.status})
		return
	}
	e.status = fmt.Sprintf("%d app rules (%d blocking), %d domains blocked", nApps, nBlock, len(domains))
	if e.FlushDNS != nil {
		e.FlushDNS()
	}
}

func (e *Enforcer) hostsPath() string {
	if e.HostsPath != "" {
		return e.HostsPath
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// WriteHosts replaces the Nexus section of a hosts file (or removes it when domains is empty),
// leaving every other line alone, and writes atomically.
func WriteHosts(path string, domains []string) error {
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	nl := "\n"
	if strings.Contains(string(raw), "\r\n") {
		nl = "\r\n"
	}
	var kept []string
	inside := false
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# BEGIN Votal Nexus"):
			inside = true
		case strings.HasPrefix(line, endMark):
			inside = false
		case !inside:
			kept = append(kept, line)
		}
	}
	for len(kept) > 0 && kept[len(kept)-1] == "" {
		kept = kept[:len(kept)-1]
	}
	if len(domains) > 0 {
		kept = append(kept, "", beginMark)
		for _, d := range domains {
			kept = append(kept, "0.0.0.0 "+d, ":: "+d)
		}
		kept = append(kept, endMark)
	}
	out := strings.Join(kept, nl) + nl
	if out == string(raw) {
		return nil
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".hosts-nexus-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.WriteString(tmp, out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := rename(tmp.Name(), path); err != nil {
		// A bind-mounted /etc/hosts (containers) or a file an antivirus holds can't be replaced:
		// rewrite it in place instead.
		if werr := os.WriteFile(path, []byte(out), mode); werr != nil {
			return fmt.Errorf("%v; writing in place: %w", err, werr)
		}
	}
	return nil
}

var rename = os.Rename // replaceable in tests

// ---- Apps -----------------------------------------------------------------------------------

// Never terminated, whatever a rule says (the server refuses these rules too).
var protectedNames = map[string]bool{}

func init() {
	for _, n := range []string{"launchd", "kernel_task", "windowserver", "loginwindow", "securityd", "opendirectoryd", "mds", "coreservicesd", "syspolicyd", "trustd", "cfprefsd", "sshd",
		"systemd", "init", "dbus-daemon", "networkmanager", "systemd-logind", "gdm", "sddm", "xorg",
		"csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe", "smss.exe", "svchost.exe", "explorer.exe", "dwm.exe", "system", "registry", "msmpeng.exe",
		"nexus-agent", "nexus-agent.exe", "osqueryd", "osqueryd.exe", "osqueryi", "osqueryi.exe",
		"system settings", "system preferences"} { // people need these to fix what compliance asks of them
		protectedNames[n] = true
	}
}

var protectedPrefixes = []string{"/system/", "/usr/libexec/", "/sbin/", `c:\windows\system32\`, "/library/application support/nexus/", `c:\program files\nexus\`, "/opt/nexus/"}

// Apple's own user apps live under /System (Music, Chess, Mail, Terminal…; Safari in a Cryptex):
// rules may stop those. The rest of /System stays off limits.
var systemAppPrefixes = []string{"/system/applications/", "/system/cryptexes/app/system/applications/", "/system/volumes/preboot/cryptexes/app/system/applications/"}

func protected(p Proc) bool {
	if p.PID <= 1 || p.PID == os.Getpid() || p.PID == os.Getppid() {
		return true
	}
	lower := strings.ToLower(p.Path)
	if protectedNames[strings.ToLower(base(p.Path))] {
		return true
	}
	for _, pre := range systemAppPrefixes {
		if strings.HasPrefix(lower, pre) {
			return false
		}
	}
	for _, pre := range protectedPrefixes {
		if strings.HasPrefix(lower, pre) {
			return true
		}
	}
	return false
}

func base(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func fold(goos string) bool { return goos != "linux" } // macOS and Windows paths are case-insensitive

// Matches says whether a rule applies to an executable path.
func Matches(r Rule, path string, sum func(string) string, goos string) bool {
	eq := func(a, b string) bool {
		if fold(goos) {
			return strings.EqualFold(a, b)
		}
		return a == b
	}
	switch r.Match {
	case "name":
		// "ollama" also matches ollama.exe, and the other way round.
		strip := func(s string) string {
			if strings.HasSuffix(strings.ToLower(s), ".exe") {
				return s[:len(s)-4]
			}
			return s
		}
		return eq(base(path), r.Value) || eq(strip(base(path)), strip(r.Value))
	case "path":
		if strings.HasSuffix(r.Value, "/") || strings.HasSuffix(r.Value, `\`) {
			if fold(goos) {
				return strings.HasPrefix(strings.ToLower(path), strings.ToLower(r.Value))
			}
			return strings.HasPrefix(path, r.Value)
		}
		return eq(path, r.Value)
	case "sha256":
		return sum != nil && strings.EqualFold(sum(path), r.Value)
	}
	return false
}

func (e *Enforcer) sum(path string) string {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<30 {
		return ""
	}
	e.mu.Lock()
	if h, ok := e.hashes[path]; ok && h.size == st.Size() && h.mod == st.ModTime().UnixNano() {
		e.mu.Unlock()
		return h.sum
	}
	e.mu.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	e.mu.Lock()
	if e.hashes == nil {
		e.hashes = map[string]hashEntry{}
	}
	e.hashes[path] = hashEntry{st.Size(), st.ModTime().UnixNano(), sum}
	e.mu.Unlock()
	return sum
}

// Scan checks running processes against the app rules once.
func (e *Enforcer) Scan() {
	rules := e.rules("app")
	if len(rules) == 0 || e.Processes == nil {
		return
	}
	procs, err := e.Processes()
	if err != nil {
		e.Log.Warn("listing processes", "err", err)
		return
	}
	needHash := false
	for _, r := range rules {
		needHash = needHash || r.Match == "sha256"
	}
	alive := map[string]bool{}
	for _, p := range procs {
		if p.Path == "" || protected(p) {
			continue
		}
		for _, r := range rules {
			var sum func(string) string
			if needHash {
				sum = e.sum
			}
			if !Matches(r, p.Path, sum, runtime.GOOS) {
				continue
			}
			if r.Mode != "block" {
				k := fmt.Sprintf("%s|%d|%s", r.ID, p.PID, p.Path)
				alive[k] = true
				e.mu.Lock()
				seen := e.monitored[k]
				e.mu.Unlock()
				if !seen {
					e.record(Event{RuleID: r.ID, Action: "would_terminate", Subject: p.Path, User: p.User})
				}
				break
			}
			if err := e.Kill(p.PID); err != nil {
				e.record(Event{RuleID: r.ID, Action: "failed", Subject: p.Path, User: p.User, Detail: "couldn't terminate: " + err.Error()})
			} else {
				e.Log.Info("terminated a blocked app", "rule", r.Name, "path", p.Path, "pid", p.PID)
				e.record(Event{RuleID: r.ID, Action: "terminated", Subject: p.Path, User: p.User})
			}
			break
		}
	}
	// Remember monitored processes while they run; a new launch is a new event.
	e.mu.Lock()
	e.monitored = alive
	e.mu.Unlock()
}

// In monitor mode a running app matches on every scan: count it once per process, not every 2 seconds.
func (e *Enforcer) record(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.addEvent(ev)
}

func (e *Enforcer) addEvent(ev Event) {
	if e.events == nil {
		e.events = map[string]*Event{}
	}
	k := ev.RuleID + "|" + ev.Action + "|" + ev.Subject + "|" + ev.User + "|" + ev.Detail
	if cur, ok := e.events[k]; ok {
		cur.Count++
		return
	}
	if len(e.events) >= 100 {
		return
	}
	ev.Count = 1
	ev.At = e.now().UTC().Format(time.RFC3339)
	e.events[k] = &ev
}

// Report is what goes in the next check-in.
func (e *Enforcer) Report() Report {
	r := e.report()
	e.settingsSoon() // re-assert settings hourly
	e.softwareSoon() // …and apps
	e.accountsSoon() // …and local accounts
	return r
}

func (e *Enforcer) report() Report {
	e.mu.Lock()
	defer e.mu.Unlock()
	r := Report{Status: e.status, Events: []Event{}, Settings: append([]settings.Result{}, e.settingsRes...), RecoveryKeys: e.pendingKeys}
	if e.softwareRes != nil {
		r.Software = append([]software.Result{}, e.softwareRes...)
	}
	if e.accountsRes != nil {
		r.Accounts = append([]accounts.Status{}, e.accountsRes...)
	}
	if e.policy != nil {
		r.Version = e.policy.Ver
	}
	for _, ev := range e.events {
		r.Events = append(r.Events, *ev)
	}
	sort.Slice(r.Events, func(i, j int) bool { return r.Events[i].At < r.Events[j].At })
	return r
}

// Delivered forgets the events a check-in carried, and remembers the recovery keys it escrowed.
func (e *Enforcer) Delivered(sent Report) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(sent.RecoveryKeys) > 0 {
		d := settings.KeysDigest(sent.RecoveryKeys)
		if err := os.WriteFile(e.escrowPath(), []byte(d), 0o600); err == nil && settings.KeysDigest(e.pendingKeys) == d {
			e.pendingKeys = nil
		}
	}
	for _, ev := range sent.Events {
		k := ev.RuleID + "|" + ev.Action + "|" + ev.Subject + "|" + ev.User + "|" + ev.Detail
		if cur, ok := e.events[k]; ok && cur.Count <= ev.Count {
			delete(e.events, k)
		} else if ok {
			cur.Count -= ev.Count
		}
	}
}

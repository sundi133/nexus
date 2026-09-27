// Package events streams every program the device starts to Nexus, in near real
// time, from osquery's event tables: Endpoint Security on macOS, ETW on Windows,
// eBPF on Linux. The agent runs its own osqueryd (own config, database, pidfile
// and logs in the agent's state folder; extensions off; osquery's watchdog on),
// tails its results log, redacts secrets from command lines and uploads batches
// every few seconds. It runs only while the organization turns it on, as root.
package events

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const queryName = "nexus_process_events"

// Event is one program start.
type Event struct {
	Time            int64    `json:"time"`
	PID             int64    `json:"pid"`
	PPID            int64    `json:"-"`
	Path            string   `json:"path"`
	Cmdline         string   `json:"cmdline"`
	User            string   `json:"user"`
	ParentPath      string   `json:"parent_path"`
	Ancestors       []string `json:"ancestors"`
	ResponsiblePath string   `json:"responsible_path"`
	Signer          string   `json:"signer"`
}

// Batch is one upload.
type Batch struct {
	Status  string  `json:"status"`
	Dropped int     `json:"dropped"`
	Events  []Event `json:"events"`
}

// Platform is what differs per OS.
type Platform struct {
	Source string   // shown in the status
	Flags  []string // turn the event publisher on
	Query  string
}

// PlatformFor returns the event source, flags and query for an OS (checked against osquery 5.23.1).
func PlatformFor(goos string) Platform {
	anc := func(parent string) string {
		return fmt.Sprintf(`LEFT JOIN processes p ON p.pid = %s
LEFT JOIN processes g1 ON g1.pid = p.parent
LEFT JOIN processes g2 ON g2.pid = g1.parent`, parent)
	}
	cols := `COALESCE(p.path, '') AS parent_path, COALESCE(g1.path, '') AS a1, COALESCE(g2.path, '') AS a2`
	switch goos {
	case "darwin":
		return Platform{
			Source: "Endpoint Security",
			Flags:  []string{"--disable_endpointsecurity=false", "--disable_endpointsecurity_fim=true"},
			Query: `SELECT e.time, e.pid, e.parent AS ppid, e.path, e.cmdline, e.username AS user, ` + cols + `,
COALESCE(r.path, '') AS responsible_path, COALESCE(NULLIF(e.team_id, ''), e.signing_id, '') AS signer
FROM es_process_events e ` + anc("e.parent") + `
LEFT JOIN processes r ON r.pid = e.responsible_pid
WHERE e.event_type = 'exec'`,
		}
	case "windows":
		return Platform{
			Source: "ETW",
			Flags:  []string{"--enable_process_etw_events=true"},
			Query: `SELECT e.time, e.pid, e.ppid AS ppid, e.path, e.cmdline, e.username AS user, ` + cols + `, '' AS responsible_path, '' AS signer
FROM process_etw_events e ` + anc("e.ppid") + `
WHERE e.type = 'ProcessStart'`,
		}
	}
	return Platform{
		Source: "eBPF",
		Flags:  []string{"--enable_bpf_events=true"},
		Query: `SELECT e.time, e.pid, e.parent AS ppid, e.path, e.cmdline, COALESCE(u.username, CAST(e.uid AS TEXT)) AS user, ` + cols + `, '' AS responsible_path, '' AS signer
FROM bpf_process_events e ` + anc("e.parent") + `
LEFT JOIN users u ON u.uid = e.uid
WHERE e.syscall = 'exec'`,
	}
}

// Collector supervises osqueryd and uploads what it sees.
type Collector struct {
	StateDir string
	GOOS     string
	Locate   func() string
	IsRoot   func() bool
	Upload   func(ctx context.Context, b Batch) error
	Log      *slog.Logger
	// Every is the upload interval (default 5 s); Interval is osquery's query interval in seconds (default 10).
	Every    time.Duration
	Interval int
	// RetryMin is the first wait after a failure (default 10 s; doubles up to 10 min).
	RetryMin time.Duration

	mu      sync.Mutex
	enabled bool
	status  string
	queue   []Event
	dropped int
	offset  int64
	inode   uint64
	proc    *exec.Cmd
	exited  chan struct{}
	stderr  *tail
	started time.Time
	lastUp  string
	lineage map[int64]proc // recent launches: pid → program and parent, to trace ancestry after they exit
}

const maxQueue = 10_000

func (c *Collector) dir() string { return filepath.Join(c.StateDir, "osquery-events") }

// SetEnabled follows the organization's setting (from each check-in).
func (c *Collector) SetEnabled(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = on
}

func (c *Collector) setStatus(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = s
}

// Run keeps osqueryd running while enabled, tails its results and uploads them.
func (c *Collector) Run(ctx context.Context) {
	every := c.Every
	if every == 0 {
		every = 5 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	backoff := time.Duration(0)
	var nextStart time.Time
	for {
		c.mu.Lock()
		on := c.enabled
		c.mu.Unlock()
		fail := func(msg string) { // a failed start or a crash: keep the reason, retry later
			c.setStatus(msg)
			backoff = min(max(backoff*2, c.retry()), 10*time.Minute)
			nextStart = time.Now().Add(backoff)
			c.Log.Warn("process events unavailable", "reason", msg, "retry_in", backoff)
		}
		alive, crashed := c.running()
		switch {
		case !on:
			c.stop()
		case alive:
			c.readResults()
			c.checkPublisher()
			if time.Since(c.startedAt()) > time.Minute {
				backoff = 0 // it's been stable
			}
		case crashed != "":
			fail(crashed)
		case time.Now().After(nextStart):
			if err := c.start(); err != nil {
				fail(err.Error())
			}
		}
		if on {
			c.flush(ctx)
		}
		select {
		case <-ctx.Done():
			c.stop()
			return
		case <-t.C:
		}
	}
}

// running says whether osqueryd is up, or why it just stopped.
func (c *Collector) running() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proc == nil {
		return false, ""
	}
	select {
	case <-c.exited:
		c.proc = nil
		return false, "osqueryd stopped: " + explain(strings.TrimSpace(c.stderr.String()))
	default:
		return true, ""
	}
}

func (c *Collector) startedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

func (c *Collector) retry() time.Duration {
	if c.RetryMin > 0 {
		return c.RetryMin
	}
	return 10 * time.Second
}

// explain turns osqueryd's own complaints into what an admin should do.
func explain(msg string) string {
	switch {
	case strings.Contains(msg, "NOT_PERMITTED") || strings.Contains(msg, "Full Disk Access") || strings.Contains(msg, "ERR_NOT_PERMITTED"):
		return "macOS refused Endpoint Security: grant Full Disk Access to the Nexus agent with an MDM privacy (PPPC) profile"
	case strings.Contains(msg, "NOT_PRIVILEGED"):
		return "Endpoint Security needs root"
	case msg == "":
		return "no output"
	}
	lines := strings.Split(msg, "\n")
	last := lines[len(lines)-1]
	if len(last) > 300 {
		last = last[:300]
	}
	return last
}

func (c *Collector) start() error {
	bin := c.Locate()
	if bin == "" {
		return errors.New("osquery isn't installed (it comes with the Nexus installers)")
	}
	if c.IsRoot != nil && !c.IsRoot() {
		return errors.New("the agent must run as root / SYSTEM to collect process events")
	}
	plat := PlatformFor(c.GOOS)
	dir := c.dir()
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		return err
	}
	interval := c.Interval
	if interval == 0 {
		interval = 10
	}
	conf := map[string]any{
		"options":  map[string]any{"schedule_splay_percent": 0},
		"schedule": map[string]any{queryName: map[string]any{"query": plat.Query, "interval": interval, "removed": false}},
	}
	data, _ := json.MarshalIndent(conf, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "osquery.conf"), data, 0o600); err != nil {
		return err
	}
	args := []string{
		"--config_path=" + filepath.Join(dir, "osquery.conf"),
		"--database_path=" + filepath.Join(dir, "db"),
		"--pidfile=" + filepath.Join(dir, "osqueryd.pid"),
		"--logger_plugin=filesystem",
		"--logger_path=" + filepath.Join(dir, "logs"),
		"--logger_rotate=true", "--logger_rotate_size=20971520", "--logger_rotate_max_files=3",
		"--disable_extensions=true",
		"--disable_events=false", "--events_expiry=60", "--events_max=100000",
		"--host_identifier=uuid",
		"--watchdog_level=0",
		"--force",
	}
	args = append(args, plat.Flags...)
	if real, err := filepath.EvalSymlinks(bin); err == nil {
		bin = real // /usr/bin/osqueryi is usually a link to osqueryd
	}
	if strings.HasPrefix(strings.ToLower(filepath.Base(bin)), "osqueryi") {
		return errors.New("the osquery found is only the interactive shell (osqueryi); process events need osqueryd")
	}
	cmd := exec.Command(bin, args...)
	errTail := &tail{max: 8 << 10}
	cmd.Stdout, cmd.Stderr = io.Discard, errTail
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("can't start osqueryd: %w", err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	c.mu.Lock()
	c.proc, c.exited, c.stderr, c.started = cmd, exited, errTail, time.Now()
	c.status = "running: osquery " + plat.Source
	c.mu.Unlock()
	c.Log.Info("process events started", "source", plat.Source)
	return nil
}

func (c *Collector) stop() {
	c.mu.Lock()
	p, exited := c.proc, c.exited
	c.proc = nil
	if p != nil {
		c.status = "stopped"
	}
	c.mu.Unlock()
	if p == nil {
		return
	}
	_ = p.Process.Signal(os.Interrupt)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		_ = p.Process.Kill()
	}
	c.Log.Info("process events stopped")
}

// checkPublisher notices osqueryd running without its event source: osquery logs
// "Event publisher not enabled: <name>: <why>" and carries on, producing nothing.
func (c *Collector) checkPublisher() {
	raw, err := os.ReadFile(filepath.Join(c.dir(), "logs", "osqueryd.INFO"))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		_, why, ok := strings.Cut(line, "Event publisher not enabled: ")
		if !ok || strings.Contains(why, "disabled via configuration") {
			continue
		}
		c.setStatus("osqueryd is running, but its event source isn't: " + explainPublisher(why))
		return
	}
}

func explainPublisher(why string) string {
	switch {
	case strings.Contains(why, "tracepoint") || strings.Contains(why, "debug/tracing"):
		return "eBPF needs the kernel's tracing filesystem (mount debugfs at /sys/kernel/debug) and a kernel with BPF support (" + why + ")"
	case strings.Contains(why, "NOT_PERMITTED"):
		return "macOS refused Endpoint Security: grant Full Disk Access to the Nexus agent with an MDM privacy (PPPC) profile"
	}
	if len(why) > 300 {
		why = why[:300]
	}
	return why
}

// readResults reads new lines from osqueryd's results log (following rotation).
func (c *Collector) readResults() {
	path := filepath.Join(c.dir(), "logs", "osqueryd.results.log")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	ino := inodeOf(st)
	c.mu.Lock()
	if ino != c.inode || st.Size() < c.offset {
		c.inode, c.offset = ino, 0 // rotated or truncated: start over
	}
	off := c.offset
	c.mu.Unlock()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return
	}
	r := bufio.NewReaderSize(f, 256<<10)
	var events []Event
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			break // a partial line waits for the next read
		}
		off += int64(len(line))
		if e, ok := parseLine(line); ok {
			events = append(events, e)
		}
	}
	c.mu.Lock()
	c.offset = off
	for i := range events {
		c.trace(&events[i])
	}
	for _, e := range events {
		if len(c.queue) >= maxQueue {
			c.dropped++
			continue
		}
		c.queue = append(c.queue, e)
	}
	c.mu.Unlock()
}

type proc struct {
	path string
	prev []string // what this pid ran before exec'ing in place (claude -c "bash …" becomes bash, same pid)
	ppid int64
	at   time.Time
}

// trace fills in an event's parent and ancestors from earlier launches (they may have exited
// before osquery's live process table was read: an AI agent's shell often has), keeping what
// osquery's own join found when the launch history doesn't know the parent. Caller holds c.mu.
func (c *Collector) trace(e *Event) {
	if c.lineage == nil || len(c.lineage) > 50_000 {
		c.prune()
	}
	cur := proc{path: e.Path, ppid: e.PPID, at: time.Now()}
	if old, ok := c.lineage[e.PID]; ok && old.ppid == e.PPID && time.Since(old.at) < 10*time.Minute {
		cur.prev = append([]string{old.path}, old.prev...) // same pid, same parent: an exec in place, not a reused pid
		if len(cur.prev) > 3 {
			cur.prev = cur.prev[:3]
		}
	}
	c.lineage[e.PID] = cur
	parent, ok := c.lineage[e.PPID]
	if !ok || e.PPID == 0 || e.PPID == e.PID {
		return
	}
	e.ParentPath = parent.path
	anc := append([]string{}, parent.prev...)
	seen := map[int64]bool{e.PID: true, e.PPID: true}
	for pid := parent.ppid; len(anc) < 4 && pid > 1 && !seen[pid]; {
		seen[pid] = true
		p, ok := c.lineage[pid]
		if !ok {
			break
		}
		anc = append(append(anc, p.path), p.prev...)
		pid = p.ppid
	}
	if len(anc) > 4 {
		anc = anc[:4]
	}
	if len(anc) > 0 || len(e.Ancestors) == 0 {
		e.Ancestors = anc
	}
}

func (c *Collector) prune() {
	keep := map[int64]proc{}
	for pid, p := range c.lineage {
		if time.Since(p.at) < 30*time.Minute {
			keep[pid] = p
		}
	}
	c.lineage = keep
}

// parseLine reads one osquery result ("event format": one row per line, action "added").
func parseLine(line []byte) (Event, bool) {
	var r struct {
		Name    string            `json:"name"`
		Action  string            `json:"action"`
		Columns map[string]string `json:"columns"`
	}
	if json.Unmarshal(bytes.TrimSpace(line), &r) != nil || r.Name != queryName || r.Action != "added" {
		return Event{}, false
	}
	col := r.Columns
	num := func(k string) int64 { n, _ := strconv.ParseInt(col[k], 10, 64); return n }
	anc := []string{}
	for _, k := range []string{"a1", "a2"} {
		if col[k] != "" {
			anc = append(anc, col[k])
		}
	}
	return Event{
		Time: num("time"), PID: num("pid"), PPID: num("ppid"), Path: col["path"], Cmdline: Redact(col["cmdline"]), User: col["user"],
		ParentPath: col["parent_path"], Ancestors: anc, ResponsiblePath: col["responsible_path"], Signer: col["signer"],
	}, col["path"] != ""
}

// flush uploads queued events (and a changed status), 2,000 at a time.
func (c *Collector) flush(ctx context.Context) {
	c.mu.Lock()
	n := min(len(c.queue), 2000)
	b := Batch{Status: c.status, Dropped: c.dropped, Events: append(make([]Event, 0, n), c.queue[:n]...)} // [] not null: the server wants a list
	changed := c.status != c.lastUp
	c.mu.Unlock()
	if n == 0 && !changed {
		return
	}
	if err := c.Upload(ctx, b); err != nil {
		c.Log.Warn("uploading process events", "err", err)
		return
	}
	c.mu.Lock()
	c.queue = c.queue[n:]
	c.dropped -= b.Dropped
	c.lastUp = b.Status
	c.mu.Unlock()
}

// Status is shown on check-in logs and in tests.
func (c *Collector) Status() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

// tail keeps the last max bytes written to it (osqueryd's stderr).
type tail struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// ---- Redaction (the server redacts again) -------------------------------------------------

var (
	secretish = `(?:password|passwd|pwd|token|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|authorization|auth[_-]?token)`
	urlCreds  = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@`)
	bearer    = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9_\-.=+/]{8,}`)
	jwt       = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`)
	token     = regexp.MustCompile(`\b(ghp_|gho_|ghu_|ghs_|github_pat_|glpat-|xox[abprs]-|sk-|sk_live_|rk_live_|AKIA|ASIA|AIza|ya29\.|ntn_|lin_api_|npm_|dop_v1_|shpat_)[A-Za-z0-9_\-.]{8,}`)
	assign    = regexp.MustCompile(`(?i)\b([A-Za-z0-9_-]*` + secretish + `[A-Za-z0-9_-]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s'"]+)`)
	flag      = regexp.MustCompile(`(?i)(^|\s)(--?[A-Za-z0-9_-]*` + secretish + `[A-Za-z0-9_-]*)(\s+)("[^"]*"|'[^']*'|[^\s-]\S*)`)
)

// Redact removes secrets from a command line and caps it.
func Redact(cmd string) string {
	cmd = urlCreds.ReplaceAllString(cmd, "${1}<redacted>@")
	cmd = bearer.ReplaceAllString(cmd, "$1 <redacted>")
	cmd = jwt.ReplaceAllString(cmd, "<redacted>")
	cmd = token.ReplaceAllString(cmd, "<redacted>")
	cmd = assign.ReplaceAllStringFunc(cmd, func(m string) string {
		p := assign.FindStringSubmatch(m)
		if strings.HasPrefix(p[3], "Bearer") || strings.HasPrefix(p[3], "Basic") || p[3] == "<redacted>" {
			return m
		}
		return p[1] + p[2] + "<redacted>"
	})
	cmd = flag.ReplaceAllStringFunc(cmd, func(m string) string {
		p := flag.FindStringSubmatch(m)
		if p[4] == "<redacted>" {
			return m
		}
		return p[1] + p[2] + p[3] + "<redacted>"
	})
	if len(cmd) > 2000 {
		cmd = cmd[:2000]
	}
	return cmd
}

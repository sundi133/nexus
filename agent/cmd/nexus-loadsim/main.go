// Command nexus-loadsim simulates a fleet of Nexus agents against a server, with the agent's own
// signed-request code (device keys, proofs, check-in client), to measure how the server holds up.
//
//	go run ./cmd/nexus-loadsim -server http://localhost:8080 -token nxe_… -devices 2000 -interval 60s -duration 10m
//
// Each device enrolls once (keys and IDs are cached in -state, so reruns reuse the fleet), then checks
// in every -interval with realistic posture and AI inventory. Its first check-in carries the osquery
// inventory pack (hundreds of software rows), like a fresh rollout. With -events N it also uploads N
// process events a minute (needs the organization's process_events setting). It prints latency
// percentiles and errors per endpoint every 10 seconds and a JSON summary at the end.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/votal-ai/nexus/agent/internal/client"
	"github.com/votal-ai/nexus/agent/internal/identity"
)

type device struct {
	ID  string `json:"id"`
	Key string `json:"key"` // base64 PEM
	c   *client.Client
	n   int
	// until: the server shed a request and asked us to wait (Retry-After); like the agent, we do.
	until time.Time
}

// backOff starts waiting out the server's Retry-After when err carries one.
func (d *device) backOff(err error) {
	if ra := client.RetryAfter(err); ra > 0 {
		d.until = time.Now().Add(ra)
	}
}

type stats struct {
	mu   sync.Mutex
	lat  map[string][]time.Duration
	errs map[string]map[string]int
}

func (s *stats) add(endpoint string, d time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lat[endpoint] = append(s.lat[endpoint], d)
	if err != nil {
		if s.errs[endpoint] == nil {
			s.errs[endpoint] = map[string]int{}
		}
		msg := err.Error()
		var p *client.Problem
		if errors.As(err, &p) {
			msg = fmt.Sprintf("%d %s", p.Status, p.Code)
		} else if len(msg) > 80 {
			msg = msg[:80]
		}
		s.errs[endpoint][msg]++
	}
}

type summary struct {
	Endpoint string         `json:"endpoint"`
	Requests int            `json:"requests"`
	PerSec   float64        `json:"per_second"`
	P50      float64        `json:"p50_ms"`
	P95      float64        `json:"p95_ms"`
	P99      float64        `json:"p99_ms"`
	Max      float64        `json:"max_ms"`
	Errors   map[string]int `json:"errors,omitempty"`
}

func (s *stats) snapshot(window time.Duration, reset bool) []summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []summary
	for ep, l := range s.lat {
		if len(l) == 0 {
			continue
		}
		sorted := append([]time.Duration(nil), l...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		pct := func(p float64) float64 { return float64(sorted[int(p*float64(len(sorted)-1))]) / 1e6 }
		out = append(out, summary{Endpoint: ep, Requests: len(l), PerSec: float64(len(l)) / window.Seconds(), P50: pct(0.5), P95: pct(0.95), P99: pct(0.99), Max: float64(sorted[len(sorted)-1]) / 1e6, Errors: s.errs[ep]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	if reset {
		s.lat, s.errs = map[string][]time.Duration{}, map[string]map[string]int{}
	}
	return out
}

func main() {
	server := flag.String("server", "http://localhost:8080", "Nexus API URL")
	token := flag.String("token", "", "enrollment token (max uses ≥ devices)")
	n := flag.Int("devices", 500, "devices to simulate")
	interval := flag.Duration("interval", 60*time.Second, "check-in interval (agents use 60s)")
	duration := flag.Duration("duration", 5*time.Minute, "how long to run")
	eventsPerMin := flag.Int("events", 0, "process events per device per minute (0: none)")
	softwareRows := flag.Int("software", 400, "software rows in the first check-in's osquery pack")
	stateDir := flag.String("state", "loadsim-state", "where device keys and IDs are kept between runs")
	enrollConc := flag.Int("enroll-concurrency", 20, "parallel enrollments")
	flag.Parse()

	// Many devices, one server: keep connections alive instead of opening one per request.
	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 1000
	http.DefaultTransport.(*http.Transport).MaxIdleConns = 2000

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st := &stats{lat: map[string][]time.Duration{}, errs: map[string]map[string]int{}}

	devices, err := fleet(ctx, *server, *token, *n, *stateDir, *enrollConc, st)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("fleet ready: %d devices; checking in every %s for %s\n", len(devices), *interval, *duration)
	if s := st.snapshot(time.Second, true); len(s) > 0 {
		for _, x := range s {
			fmt.Printf("  enroll: %d requests, p50 %.0f ms, p95 %.0f ms, errors %v\n", x.Requests, x.P50, x.P95, x.Errors)
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()
	var wg sync.WaitGroup
	sw := software(*softwareRows)
	for i, d := range devices {
		wg.Add(1)
		go func(i int, d *device) {
			defer wg.Done()
			// Spread first check-ins over one interval, like a real fleet.
			select {
			case <-runCtx.Done():
				return
			case <-time.After(time.Duration(float64(*interval) * float64(i) / float64(len(devices)))):
			}
			t := time.NewTicker(*interval)
			defer t.Stop()
			var evT <-chan time.Time
			if *eventsPerMin > 0 {
				et := time.NewTicker(10 * time.Second)
				defer et.Stop()
				evT = et.C
			}
			checkin(runCtx, d, sw, st)
			for {
				select {
				case <-runCtx.Done():
					return
				case <-t.C:
					checkin(runCtx, d, sw, st)
				case <-evT:
					uploadEvents(runCtx, d, max(1, *eventsPerMin/6), st)
				}
			}
		}(i, d)
	}
	start := time.Now()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	var all []summary
	go func() { wg.Wait(); cancel() }()
	for loop := true; loop; {
		select {
		case <-runCtx.Done():
			loop = false
		case <-tick.C:
			for _, s := range st.snapshot(10*time.Second, false) {
				fmt.Printf("%5.0fs %-18s %6d req  %6.1f/s  p50 %6.0f ms  p95 %6.0f ms  p99 %6.0f ms  max %6.0f ms  errors %v\n",
					time.Since(start).Seconds(), s.Endpoint, s.Requests, s.PerSec, s.P50, s.P95, s.P99, s.Max, s.Errors)
			}
			all = append(all, st.snapshot(10*time.Second, true)...)
		}
	}
	all = append(all, st.snapshot(time.Since(start), true)...)
	out, _ := json.MarshalIndent(merge(all, time.Since(start)), "", "  ")
	fmt.Println(string(out))
}

// merge folds the periodic windows into one summary per endpoint (percentiles: the worst window's).
func merge(windows []summary, total time.Duration) []summary {
	by := map[string]*summary{}
	for _, w := range windows {
		m, ok := by[w.Endpoint]
		if !ok {
			c := w
			c.Errors = map[string]int{}
			m = &c
			m.Requests = 0
			by[w.Endpoint] = m
		}
		m.Requests += w.Requests
		m.P50 = max(m.P50, w.P50)
		m.P95 = max(m.P95, w.P95)
		m.P99 = max(m.P99, w.P99)
		m.Max = max(m.Max, w.Max)
		for k, v := range w.Errors {
			m.Errors[k] += v
		}
	}
	var out []summary
	for _, m := range by {
		m.PerSec = float64(m.Requests) / total.Seconds()
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out
}

func fleet(ctx context.Context, server, token string, n int, dir string, conc int, st *stats) ([]*device, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "devices.json")
	var saved []*device
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &saved)
	}
	var mu sync.Mutex
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	var failed atomic.Int32
	for i := len(saved); i < n; i++ {
		if token == "" {
			return nil, fmt.Errorf("%d devices cached, %d asked: pass -token to enroll the rest", len(saved), n)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			key, err := identity.Generate()
			if err != nil {
				failed.Add(1)
				return
			}
			c, err := client.New(server, key, "")
			if err != nil {
				failed.Add(1)
				return
			}
			t0 := time.Now()
			res, err := c.Enroll(ctx, token, client.DeviceInfo{Hostname: fmt.Sprintf("sim-%05d", i), Platform: []string{"macos", "windows", "linux"}[i%3], OSName: "Sim", OSVersion: "15.1", Arch: "arm64", Model: "Simulated", Serial: fmt.Sprintf("SIM%07d", i), AgentVersion: "0.9.0-sim"})
			st.add("enroll", time.Since(t0), err)
			if err != nil {
				failed.Add(1)
				return
			}
			pem, _ := key.MarshalPEM()
			mu.Lock()
			saved = append(saved, &device{ID: res.DeviceID, Key: base64.StdEncoding.EncodeToString(pem)})
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	data, _ := json.Marshal(saved)
	_ = os.WriteFile(path, data, 0o600)
	if f := failed.Load(); f > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d enrollments failed\n", f)
	}
	if len(saved) > n {
		saved = saved[:n]
	}
	for _, d := range saved {
		pem, _ := base64.StdEncoding.DecodeString(d.Key)
		key, err := identity.ParsePEM(pem)
		if err != nil {
			return nil, err
		}
		if d.c, err = client.New(server, key, d.ID); err != nil {
			return nil, err
		}
	}
	return saved, nil
}

type row = map[string]string

func software(n int) []row {
	out := make([]row, n)
	for i := range out {
		out[i] = row{"name": fmt.Sprintf("App %d", i%350), "version": fmt.Sprintf("%d.%d.%d", 1+i%9, i%20, i%7), "source": []string{"app", "homebrew", "program", "deb"}[i%4], "publisher": fmt.Sprintf("com.vendor%d.app", i%120)}
	}
	return out
}

func checkin(ctx context.Context, d *device, sw []row, st *stats) {
	if time.Now().Before(d.until) {
		return
	}
	d.n++
	// Stable posture per device, like a real fleet: about 5–10% fail a check, and keep failing it.
	h := 0
	for _, c := range d.ID {
		h = h*31 + int(c)
	}
	onOff := func(p float64) map[string]string {
		if float64((h>>3)%1000)/1000 < p {
			return map[string]string{"status": "on"}
		}
		return map[string]string{"status": "off"}
	}
	payload := map[string]any{
		"device":  map[string]any{"agent_version": "0.9.0-sim"},
		"posture": map[string]any{"disk_encryption": onOff(0.95), "firewall": onOff(0.9), "screen_lock": map[string]any{"status": "on", "delay_seconds": 60}, "system_integrity": onOff(0.99)},
	}
	if d.n == 1 || d.n%15 == 0 { // inventory on the first check-in and every 15 minutes, as the agent does
		payload["inventory"] = map[string]any{"cpu": "Sim CPU", "memory_bytes": 17179869184, "ai": map[string]any{
			"tools": []map[string]any{{"name": "Cursor", "kind": "app", "version": "1.5.0"}, {"name": "Claude Code", "kind": "cli", "user": "sim"}},
			"mcp_servers": []map[string]any{
				{"client": "Cursor", "user": "sim", "scope": "user", "name": "github", "transport": "http", "url": "https://api.githubcopilot.com/mcp/"},
				{"client": "Claude Desktop", "user": "sim", "scope": "user", "name": "fs", "transport": "stdio", "command": "npx", "package": "@modelcontextprotocol/server-filesystem"},
			},
		}}
	}
	if d.n == 1 { // a fresh rollout: every device sends its osquery pack at once
		payload["osquery"] = map[string]any{"available": true, "version": "5.23.1", "collected_at": time.Now().UTC().Format(time.RFC3339), "results": []map[string]any{{"name": "software", "rows": sw}, {"name": "listening_ports", "rows": []row{{"process": "sshd", "port": "22", "protocol": "tcp", "address": "0.0.0.0"}}}}}
	}
	t0 := time.Now()
	_, err := d.c.Checkin(ctx, payload)
	if ctx.Err() != nil {
		return
	}
	name := "checkin"
	if d.n == 1 {
		name = "checkin+osquery"
	}
	st.add(name, time.Since(t0), err)
	if err != nil {
		d.n-- // the agent sends the same report again next time
		d.backOff(err)
	}
}

func uploadEvents(ctx context.Context, d *device, k int, st *stats) {
	if time.Now().Before(d.until) {
		return
	}
	now := time.Now().Unix()
	evs := make([]map[string]any, k)
	for i := range evs {
		evs[i] = map[string]any{"time": now, "pid": rand.IntN(60000), "path": "/usr/bin/git", "cmdline": "git status", "user": "sim", "parent_path": "/bin/zsh", "ancestors": []string{"/Applications/iTerm.app/Contents/MacOS/iTerm2"}}
	}
	t0 := time.Now()
	err := d.c.Events(ctx, map[string]any{"status": "running: sim", "dropped": 0, "events": evs})
	if ctx.Err() != nil {
		return
	}
	st.add("events", time.Since(t0), err)
	d.backOff(err)
}

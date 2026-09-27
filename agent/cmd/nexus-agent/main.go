// nexus-agent reports device posture to Votal Nexus.
//
//	sudo nexus-agent install --server https://api.example.com --token nxe_…   # enroll + run at boot
//	sudo nexus-agent uninstall [--purge]
//	nexus-agent enroll --server https://api.example.com --token nxe_…
//	nexus-agent run            # check in forever (run as a system service)
//	nexus-agent run --once     # one check-in, then exit
//	nexus-agent posture        # print what would be reported, without sending
//	nexus-agent status         # show enrollment
//	nexus-agent selftest       # used by the updater to vet a new binary before installing it
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/votal-ai/nexus/agent/internal/client"
	"github.com/votal-ai/nexus/agent/internal/collect"
	"github.com/votal-ai/nexus/agent/internal/command"
	"github.com/votal-ai/nexus/agent/internal/enforce"
	"github.com/votal-ai/nexus/agent/internal/events"
	"github.com/votal-ai/nexus/agent/internal/identity"
	"github.com/votal-ai/nexus/agent/internal/local"
	"github.com/votal-ai/nexus/agent/internal/osquery"
	"github.com/votal-ai/nexus/agent/internal/release"
	"github.com/votal-ai/nexus/agent/internal/run"
	"github.com/votal-ai/nexus/agent/internal/service"
	"github.com/votal-ai/nexus/agent/internal/settings"
	"github.com/votal-ai/nexus/agent/internal/software"
	"github.com/votal-ai/nexus/agent/internal/state"
	"github.com/votal-ai/nexus/agent/internal/update"
	"github.com/votal-ai/nexus/agent/internal/updates"
)

// Set at build time:
//
//	-ldflags "-X main.version=1.2.3 -X main.releaseKeys=<base64 Ed25519 public key>[,<next key>]"
//
// Without release keys the agent can't verify, and so never installs, updates.
var (
	version     = "0.1.0-dev"
	releaseKeys = ""
	// testBreak builds deliberately broken releases to exercise the update
	// safety nets end to end ("selftest" fails the pre-install check, "crash"
	// dies right after starting). Empty in every real build.
	testBreak = ""
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	stateDir := fs.String("state-dir", state.DefaultDir(), "where the device key and enrollment are stored")
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd {
	case "enroll":
		server := fs.String("server", "", "Nexus API URL")
		token := fs.String("token", "", "enrollment token (nxe_…)")
		_ = fs.Parse(args)
		err = enroll(ctx, state.Store{Dir: *stateDir}, *server, *token)
	case "install":
		server := fs.String("server", "", "Nexus API URL (to enroll)")
		token := fs.String("token", "", "enrollment token (to enroll)")
		config := fs.String("config", "", "file with server= and token= lines (MDM deployments); deleted after use")
		_ = fs.Parse(args)
		err = install(ctx, state.Store{Dir: *stateDir}, *server, *token, *config)
	case "write-enroll-config":
		// Used by the Windows installer (a step whose command line it doesn't log): writes the
		// enroll.conf the service enrolls from, without the token passing through the MSI log.
		server := fs.String("server", "", "Nexus API URL")
		token := fs.String("token", "", "enrollment token (nxe_…)")
		_ = fs.Parse(args)
		if err = requireAdmin(); err == nil {
			err = writeEnrollConfig(state.Store{Dir: *stateDir}, *server, *token)
		}
	case "uninstall":
		purge := fs.Bool("purge", false, "also delete the device key and enrollment")
		_ = fs.Parse(args)
		err = uninstall(state.Store{Dir: *stateDir}, *purge)
	case "run":
		once := fs.Bool("once", false, "check in once and exit")
		_ = fs.Parse(args)
		// Under the Windows SCM, run as a service; elsewhere launchd/systemd run us as a plain process.
		if isSvc, serr := service.RunAsService(func(ctx context.Context) error { return runAgent(ctx, state.Store{Dir: *stateDir}, false, log) }); isSvc || serr != nil {
			err = serr
			break
		}
		err = runAgent(ctx, state.Store{Dir: *stateDir}, *once, log)
		if errors.Is(err, update.ErrRestart) {
			err = restart(log)
		}
	case "query":
		// Local troubleshooting: the same osquery and the same SQL rules as a live query.
		_ = fs.Parse(args)
		bin := osquery.Locate()
		if bin == "" {
			err = errors.New("osquery isn't installed (Nexus installers bundle it; or set NEXUS_OSQUERY_PATH)")
			break
		}
		if fs.NArg() != 1 {
			err = errors.New(`usage: nexus-agent query "SELECT …"`)
			break
		}
		r := osquery.Runner{Bin: bin}
		fmt.Fprintf(os.Stderr, "osquery %s at %s\n", r.Version(ctx), bin)
		rows, _, qerr := r.Query(ctx, fs.Arg(0), 0)
		if qerr != nil {
			err = qerr
			break
		}
		out, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(out))
	case "posture":
		_ = fs.Parse(args)
		out, _ := json.MarshalIndent(collect.Collect(ctx), "", "  ")
		fmt.Println(string(out))
	case "status":
		_ = fs.Parse(args)
		_, e, lerr := state.Store{Dir: *stateDir}.Load()
		if lerr != nil {
			err = lerr
			break
		}
		fmt.Printf("Enrolled in %s\nDevice ID: %s\nServer:    %s\nAgent:     %s\n", e.Organization, e.DeviceID, e.Server, version)
	case "version":
		fmt.Println(version)
	case "selftest":
		// The updater runs a downloaded binary this way before swapping it in:
		// it must start, parse its own trust anchors, and report its version.
		if _, kerr := release.ParseKeys(releaseKeys); kerr != nil {
			err = kerr
			break
		}
		if testBreak == "selftest" {
			err = errors.New("deliberately broken build (testBreak=selftest)")
			break
		}
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nexus-agent <enroll|run|posture|query|status|version> [flags]")
}

func enroll(ctx context.Context, store state.Store, server, token string) error {
	if server == "" || token == "" {
		return errors.New("--server and --token are required")
	}
	if _, _, err := store.Load(); err == nil {
		return fmt.Errorf("already enrolled (state in %s); remove it first to re-enroll", store.Dir)
	}
	key, err := identity.Generate()
	if err != nil {
		return err
	}
	c, err := client.New(server, key, "")
	if err != nil {
		return err
	}
	snap := deviceSnapshot(ctx)
	info := client.DeviceInfo{
		Hostname: snap.Device.Hostname, Platform: snap.Device.Platform, OSName: snap.Device.OSName,
		OSVersion: snap.Device.OSVersion, OSBuild: snap.Device.OSBuild, Arch: snap.Device.Arch,
		Model: snap.Device.Model, Serial: snap.Device.Serial, AgentVersion: version,
	}
	res, err := c.Enroll(ctx, token, info)
	// A fleet-wide rollout can arrive all at once: when the server says it's busy, wait as asked
	// (up to about 5 minutes in all) instead of failing the install.
	for waited := time.Duration(0); client.RetryAfter(err) > 0 && waited < 5*time.Minute; {
		ra := client.RetryAfter(err)
		fmt.Fprintf(os.Stderr, "The server is busy; retrying enrollment in %s.\n", ra)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(ra):
		}
		waited += ra
		res, err = c.Enroll(ctx, token, info)
	}
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	if err := store.Save(key, state.Enrollment{Server: server, DeviceID: res.DeviceID, Organization: res.Organization, WebOrigin: res.WebOrigin}); err != nil {
		return fmt.Errorf("enrolled, but saving state failed: %w", err)
	}
	if err := (&command.Runner{StateDir: store.Dir}).Pin(res.CommandKey); err != nil {
		return fmt.Errorf("enrolled, but pinning the command key failed: %w", err)
	}
	fmt.Printf("Enrolled %s in %s (device %s).\nStart reporting with: nexus-agent run\n", snap.Device.Hostname, res.Organization, res.DeviceID)
	return nil
}

func runAgent(ctx context.Context, store state.Store, once bool, log *slog.Logger) error {
	key, e, err := store.Load()
	if errors.Is(err, state.ErrNotEnrolled) && !once {
		// Installed but not enrolled yet (an MSI without TOKEN, or enroll.conf still to come):
		// wait rather than exit, so the service doesn't crash-loop.
		if err := awaitEnrollment(ctx, store, log); err != nil {
			return err
		}
		key, e, err = store.Load()
	}
	if err != nil {
		return err
	}
	if err := store.Prepare(); err != nil { // also tightens folders created by older versions
		log.Warn("could not restrict the state folder", "dir", store.Dir, "err", err)
	}
	if err := os.Remove(store.EnrollConfig()); err == nil {
		log.Info("removed an unused enroll.conf: this device is already enrolled") // e.g. an upgrade run with TOKEN= again
	}
	c, err := client.New(e.Server, key, e.DeviceID)
	if err != nil {
		return err
	}
	// The console origin the loopback server answers; the server may move it, so follow check-ins.
	var origin atomic.Value
	origin.Store(e.WebOrigin)
	onCheckin := func(res *client.CheckinResult) {
		if res.WebOrigin != "" && res.WebOrigin != origin.Load().(string) {
			origin.Store(res.WebOrigin)
			e.WebOrigin = res.WebOrigin
			if err := store.Save(key, *e); err != nil {
				log.Warn("could not save the console origin", "err", err)
			}
		}
	}
	runner := &command.Runner{StateDir: store.Dir, DeviceID: e.DeviceID, Exec: command.Actions(), ArgExec: map[string]command.ArgExecutor{"osquery": command.QueryAction(osquery.Locate), "script": command.ScriptAction(store.Dir)}, Log: log}
	ownHost := ""
	if u, perr := url.Parse(e.Server); perr == nil {
		ownHost = u.Hostname()
	}
	// Apps the organization assigns: installed and removed in the background, as root/SYSTEM.
	apps := &software.Manager{Sys: software.Sys{GOOS: runtime.GOOS, Dir: filepath.Join(store.Dir, "downloads"), Download: software.Download,
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			return string(out), err
		},
		Has:    func(n string) bool { _, err := exec.LookPath(n); return err == nil },
		Winget: func() string { return software.FindWinget(exec.LookPath) }}}
	enforcer := &enforce.Enforcer{StateDir: store.Dir, DeviceID: e.DeviceID, Key: runner.Key, OwnHost: ownHost, Log: log,
		Processes: enforce.ListProcesses, Kill: enforce.KillProcess, FlushDNS: enforce.FlushDNS,
		ApplySettings: func(d settings.Desired) settings.Outcome {
			return settings.Apply(settings.OS{Root: requireAdmin() == nil}, runtime.GOOS, d)
		},
		ApplySoftware: func(items []software.Item) []software.Result {
			if err := requireAdmin(); err != nil {
				out := make([]software.Result, 0, len(items))
				for _, it := range items {
					out = append(out, software.Result{ID: it.ID, Status: software.Unsupported, Detail: "the agent isn't running as root/SYSTEM", At: time.Now().UTC().Format(time.RFC3339)})
				}
				return out
			}
			return apps.Apply(context.Background(), items)
		}}
	enforcer.Load() // the last rules apply from boot, before the first check-in
	// OS updates: checked in the background every 6 hours (slow), reported with the inventory.
	updateChecker := &updates.Checker{GOOS: runtime.GOOS, Every: 6 * time.Hour,
		Run: func(ctx context.Context, name string, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			return string(out), err
		},
		Has: func(n string) bool { _, err := exec.LookPath(n); return err == nil }}
	runner.ArgExec["updates"] = command.UpdatesAction(command.Actions()["restart"], updateChecker.Recheck)
	collectWithUpdates := func(ctx context.Context) collect.Snapshot {
		s := collect.Collect(ctx)
		if r := updateChecker.Report(); r != nil {
			s.Inventory.Updates = r
		}
		return s
	}
	loop := &run.Loop{Client: c, Version: version, Log: log, Collect: collectWithUpdates, OnCheckin: onCheckin, Enforcer: enforcer,
		Commands: runner,
		Osquery: func(ctx context.Context) osquery.Report {
			return osquery.Collect(ctx, osquery.Locate(), runtime.GOOS, time.Now())
		}}
	if once {
		res, err := loop.Once(ctx, 0)
		if err != nil {
			return err
		}
		enforcer.Scan() // one pass with the rules this check-in brought
		if len(enforcer.Report().Events) > 0 {
			loop.MarkPending()
		}
		// Commands ran during this check-in: report them now, since there's no next one.
		if loop.Pending() {
			if res, err = loop.Once(ctx, 0); err != nil {
				return err
			}
		}
		fmt.Printf("Checked in. Compliance: %s\n", res.Compliance)
		return nil
	}
	log.Info("nexus agent started", "device", e.DeviceID, "server", e.Server, "version", version)
	// Real-time process events, while the organization turns them on (each check-in says).
	collector := &events.Collector{StateDir: store.Dir, GOOS: runtime.GOOS, Locate: osquery.Locate, IsRoot: func() bool { return requireAdmin() == nil }, Log: log}
	collector.Upload = func(ctx context.Context, b events.Batch) error {
		err := c.Events(ctx, b)
		var p *client.Problem
		if errors.As(err, &p) && p.Code == "events_off" {
			collector.SetEnabled(false) // turned off since the last check-in
			return nil
		}
		return err
	}
	prev := loop.OnCheckin
	loop.OnCheckin = func(res *client.CheckinResult) {
		prev(res)
		collector.SetEnabled(res.ProcessEvents)
	}
	go collector.Run(ctx)
	go func() { // the app-rule watcher
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				enforcer.Scan()
			}
		}
	}()
	upd, err := newUpdater(store, c, log)
	if err != nil {
		log.Warn("self-update unavailable", "err", err)
	} else {
		// A freshly installed version that keeps failing is rolled back here.
		if err := upd.Recover(); err != nil {
			return err
		}
		if testBreak == "crash" {
			return errors.New("deliberately broken build (testBreak=crash)")
		}
		loop.Updater = upd
	}
	lsrv := &local.Server{Key: key, DeviceID: e.DeviceID, Origin: func() string { return origin.Load().(string) }, Log: log}
	if ln, err := lsrv.Listen(); err != nil {
		log.Warn("browser device checks unavailable", "err", err)
	} else {
		defer ln.Close()
		go func() {
			if err := lsrv.Serve(ln); err != nil {
				log.Error("local server stopped", "err", err)
			}
		}()
		log.Info("answering browser device checks", "addr", local.Addr, "origin", e.WebOrigin)
	}
	err = loop.Run(ctx)
	if errors.Is(err, client.ErrNotEnrolled) {
		log.Error("this device was removed from Nexus; clearing local enrollment")
		_ = store.Forget()
	}
	return err
}

var enrollRetry = 30 * time.Second // first retry; doubles up to 10 minutes

// awaitEnrollment enrolls from the installer's enroll.conf when it appears
// (retrying with backoff while the network or token is not ready), or returns
// once someone enrolls the device by hand.
// deviceSnapshot describes the device for enrollment. Collecting is slow on Windows (several
// PowerShell calls), so one snapshot is reused while enrollment retries. Replaceable in tests.
var deviceSnapshot = func() func(context.Context) collect.Snapshot {
	var (
		mu   sync.Mutex
		snap *collect.Snapshot
	)
	return func(ctx context.Context) collect.Snapshot {
		mu.Lock()
		defer mu.Unlock()
		if snap == nil {
			s := collect.Collect(ctx)
			snap = &s
		}
		return *snap
	}
}()

func awaitEnrollment(ctx context.Context, store state.Store, log *slog.Logger) error {
	wait, waiting := enrollRetry, false
	for {
		if _, _, err := store.Load(); err == nil {
			return nil
		} else if !errors.Is(err, state.ErrNotEnrolled) {
			return err
		}
		conf := store.EnrollConfig()
		if server, token, err := readConfig(conf); err == nil {
			if err := enroll(ctx, store, server, token); err != nil {
				log.Warn("enrolling from "+conf+" failed; will retry", "err", err, "in", wait)
			} else {
				_ = os.Remove(conf) // it holds an enrollment secret
				log.Info("enrolled from " + conf)
				continue
			}
		} else if !waiting {
			log.Info("not enrolled yet: waiting for "+conf+" or `nexus-agent install --server … --token …`", "dir", store.Dir)
			waiting = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if wait < 10*time.Minute {
			wait *= 2
		}
	}
}

func newUpdater(store state.Store, c *client.Client, log *slog.Logger) (*update.Updater, error) {
	keys, err := release.ParseKeys(releaseKeys)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		log.Warn("this build has no release keys; updates offered by the server will be refused")
	}
	return &update.Updater{Keys: keys, Current: version, Exe: exe, StateDir: store.Dir, Download: c.Download, SelfTest: update.ExecSelfTest, Log: log}, nil
}

// install copies this binary to the system location, enrolls (if given a
// token and not yet enrolled) and registers the agent to run at boot.
func install(ctx context.Context, store state.Store, server, token, config string) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	if config != "" {
		var err error
		if server, token, err = readConfig(config); err != nil {
			return err
		}
	}
	bin := filepath.Join(service.InstallDir, service.BinName)
	if err := service.CopyExecutable(bin); err != nil {
		return fmt.Errorf("installing %s: %w", bin, err)
	}
	if _, _, err := store.Load(); errors.Is(err, state.ErrNotEnrolled) {
		if token == "" {
			return errors.New("not enrolled yet: pass --server and --token (or --config)")
		}
		if err := enroll(ctx, store, server, token); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if config != "" {
		_ = os.Remove(config) // it holds an enrollment secret
	}
	if err := service.Install(bin, store.Dir); err != nil {
		return fmt.Errorf("registering the service: %w", err)
	}
	fmt.Printf("Installed %s and started %s.\n", bin, service.Describe())
	return nil
}

func uninstall(store state.Store, purge bool) error {
	if err := requireAdmin(); err != nil {
		return err
	}
	if err := service.Uninstall(); err != nil {
		return err
	}
	bin := filepath.Join(service.InstallDir, service.BinName)
	for _, p := range []string{bin, bin + ".previous", bin + ".failed"} {
		_ = os.Remove(p)
	}
	// macOS packages have no uninstaller: remove the osquery the .pkg bundled, and the receipt.
	// (Linux and Windows packages own their files; the package manager removes them.)
	if runtime.GOOS == "darwin" {
		_ = os.RemoveAll(filepath.Join(filepath.Dir(service.InstallDir), "osquery"))
		_ = exec.Command("pkgutil", "--forget", "ai.votal.nexus-agent").Run()
	}
	if purge {
		if err := os.RemoveAll(store.Dir); err != nil {
			return err
		}
		fmt.Println("Removed the agent, its device key and enrollment. Remove the device in the Nexus console too.")
		return nil
	}
	fmt.Println("Removed the agent. Its device key is kept, so reinstalling resumes the same device (use --purge to delete it).")
	return nil
}

// writeEnrollConfig writes server= and token= lines for the service to enroll from (it deletes the file after).
func writeEnrollConfig(store state.Store, server, token string) error {
	server, token = strings.TrimSpace(server), strings.TrimSpace(token)
	if server == "" || token == "" {
		return errors.New("--server and --token are required")
	}
	if !strings.HasPrefix(token, "nxe_") || strings.ContainsAny(token, " \t\r\n=") {
		return errors.New("that isn't an enrollment token (nxe_…)")
	}
	if strings.ContainsAny(server, " \t\r\n") {
		return errors.New("invalid server URL")
	}
	if err := os.MkdirAll(store.Dir, 0o700); err != nil {
		return err
	}
	tmp := store.EnrollConfig() + ".tmp"
	if err := os.WriteFile(tmp, []byte("server="+server+"\ntoken="+token+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, store.EnrollConfig())
}

// readConfig parses `server=` / `token=` lines, as an MDM drops them before installing the package.
func readConfig(path string) (server, token string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "server":
			server = strings.TrimSpace(v)
		case "token":
			token = strings.TrimSpace(v)
		}
	}
	if server == "" || token == "" {
		return "", "", fmt.Errorf("%s must set server= and token=", path)
	}
	return server, token, nil
}

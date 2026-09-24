// nexus-agent reports device posture to Votal Nexus.
//
//	nexus-agent enroll --server https://api.example.com --token nxe_…
//	nexus-agent run            # check in forever (run as a system service)
//	nexus-agent run --once     # one check-in, then exit
//	nexus-agent posture        # print what would be reported, without sending
//	nexus-agent status         # show enrollment
package main

import (
	"sync/atomic"

	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/votal-ai/nexus/agent/internal/client"
	"github.com/votal-ai/nexus/agent/internal/collect"
	"github.com/votal-ai/nexus/agent/internal/identity"
	"github.com/votal-ai/nexus/agent/internal/local"
	"github.com/votal-ai/nexus/agent/internal/run"
	"github.com/votal-ai/nexus/agent/internal/state"
)

// version is set at build time: -ldflags "-X main.version=1.2.3"
var version = "0.1.0-dev"

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
	case "run":
		once := fs.Bool("once", false, "check in once and exit")
		_ = fs.Parse(args)
		err = runAgent(ctx, state.Store{Dir: *stateDir}, *once, log)
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
	fmt.Fprintln(os.Stderr, "usage: nexus-agent <enroll|run|posture|status|version> [flags]")
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
	snap := collect.Collect(ctx)
	res, err := c.Enroll(ctx, token, client.DeviceInfo{
		Hostname: snap.Device.Hostname, Platform: snap.Device.Platform, OSName: snap.Device.OSName,
		OSVersion: snap.Device.OSVersion, OSBuild: snap.Device.OSBuild, Arch: snap.Device.Arch,
		Model: snap.Device.Model, Serial: snap.Device.Serial, AgentVersion: version,
	})
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	if err := store.Save(key, state.Enrollment{Server: server, DeviceID: res.DeviceID, Organization: res.Organization, WebOrigin: res.WebOrigin}); err != nil {
		return fmt.Errorf("enrolled, but saving state failed: %w", err)
	}
	fmt.Printf("Enrolled %s in %s (device %s).\nStart reporting with: nexus-agent run\n", snap.Device.Hostname, res.Organization, res.DeviceID)
	return nil
}

func runAgent(ctx context.Context, store state.Store, once bool, log *slog.Logger) error {
	key, e, err := store.Load()
	if err != nil {
		return err
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
	loop := &run.Loop{Client: c, Version: version, Log: log, Collect: collect.Collect, OnCheckin: onCheckin}
	if once {
		res, err := loop.Once(ctx, 0)
		if err != nil {
			return err
		}
		fmt.Printf("Checked in. Compliance: %s\n", res.Compliance)
		return nil
	}
	log.Info("nexus agent started", "device", e.DeviceID, "server", e.Server, "version", version)
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

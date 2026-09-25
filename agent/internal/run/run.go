// Package run is the agent's check-in loop.
package run

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/votal-ai/nexus/agent/internal/client"
	"github.com/votal-ai/nexus/agent/internal/collect"
	"github.com/votal-ai/nexus/agent/internal/command"
	"github.com/votal-ai/nexus/agent/internal/osquery"
	"github.com/votal-ai/nexus/agent/internal/release"
	"github.com/votal-ai/nexus/agent/internal/update"
)

// Updater is the self-update hook (implemented by update.Updater).
type Updater interface {
	Apply(ctx context.Context, o release.Offer) error
	Health(ok bool) error
	Result() *release.Result
	ClearResult(reported *release.Result)
}

type Checkiner interface {
	Checkin(ctx context.Context, payload any) (*client.CheckinResult, error)
}

type Loop struct {
	Client  Checkiner
	Version string
	Log     *slog.Logger
	Collect func(context.Context) collect.Snapshot
	// OnCheckin, if set, sees every successful check-in result.
	OnCheckin func(*client.CheckinResult)
	// Updater, if set, reports update outcomes and applies offered updates (Run only).
	Updater Updater
	// Commands, if set, runs signed actions from the server and reports how they went.
	Commands *command.Runner
	// Osquery, if set, collects the osquery inventory pack (slow: seconds), every OsqueryEvery.
	Osquery      func(context.Context) osquery.Report
	OsqueryEvery time.Duration

	lastInventory     [32]byte
	lastInventoryTime time.Time
	pending           []command.Result // to report on the next check-in
	osqueryRan        time.Time        // last collection
	osquerySent       time.Time        // last time a report went out
	osqueryHash       [32]byte
	osqueryReport     *osquery.Report // collected, not yet delivered
	soon              bool            // check in again right away (to report, or after a refresh)
}

// Once performs one check-in. Inventory is sent when it changed or every inventoryEvery.
func (l *Loop) Once(ctx context.Context, inventoryEvery time.Duration) (*client.CheckinResult, error) {
	snap := l.Collect(ctx)
	payload := map[string]any{
		"device": map[string]any{
			"hostname": snap.Device.Hostname, "os_name": snap.Device.OSName, "os_version": snap.Device.OSVersion,
			"os_build": snap.Device.OSBuild, "arch": snap.Device.Arch, "model": snap.Device.Model,
			"serial": snap.Device.Serial, "agent_version": l.Version,
		},
		"posture": snap.Posture,
	}
	inv, _ := json.Marshal(snap.Inventory)
	sum := sha256.Sum256(inv)
	sendInventory := sum != l.lastInventory || time.Since(l.lastInventoryTime) >= inventoryEvery
	if sendInventory {
		payload["inventory"] = snap.Inventory
	}
	sentOsquery := l.osqueryPayload(ctx)
	if sentOsquery != nil {
		payload["osquery"] = sentOsquery
	}
	sentResults := len(l.pending)
	if sentResults > 0 {
		payload["command_results"] = l.pending
	}
	var reported *release.Result
	if l.Updater != nil {
		if reported = l.Updater.Result(); reported != nil {
			payload["update_result"] = reported
		}
	}
	res, err := l.Client.Checkin(ctx, payload)
	if err == nil && reported != nil {
		l.Updater.ClearResult(reported)
	}
	if err == nil && sendInventory {
		l.lastInventory, l.lastInventoryTime = sum, time.Now()
	}
	if err == nil && sentOsquery != nil {
		l.osquerySent, l.osqueryReport = time.Now(), nil
	}
	if err == nil && res.OsqueryInterval > 0 {
		l.OsqueryEvery = time.Duration(res.OsqueryInterval) * time.Second
	}
	if err == nil && l.OnCheckin != nil {
		l.OnCheckin(res)
	}
	if err == nil {
		l.pending = l.pending[sentResults:]
		if l.Commands != nil {
			if perr := l.Commands.Pin(res.CommandKey); perr != nil {
				l.Log.Warn("command key", "err", perr)
			}
			if len(res.Commands) > 0 {
				results := l.Commands.Handle(ctx, res.Commands)
				l.pending = append(l.pending, results...)
				l.soon = len(results) > 0
				l.lastInventoryTime = time.Time{} // a refresh sends full inventory
				l.osqueryRan = time.Time{}        // …and collects osquery again
			}
		}
	}
	return res, err
}

// osqueryPayload collects the pack when it's due, and returns a report to send:
// when it changed, when the last one is a day old, or when the last send failed.
func (l *Loop) osqueryPayload(ctx context.Context) *osquery.Report {
	if l.Osquery == nil {
		return nil
	}
	every := l.OsqueryEvery
	if every <= 0 {
		every = 6 * time.Hour
	}
	if l.osqueryReport == nil && time.Since(l.osqueryRan) >= every {
		rep := l.Osquery(ctx)
		l.osqueryRan = time.Now()
		body, _ := json.Marshal(rep.Results)
		sum := sha256.Sum256(append([]byte(rep.Version), body...))
		if sum != l.osqueryHash || time.Since(l.osquerySent) >= 24*time.Hour {
			l.osqueryHash, l.osqueryReport = sum, &rep
		}
	}
	return l.osqueryReport
}

// Run checks in until ctx is cancelled, the server says the device was
// removed, or an update needs a restart (update.ErrRestart).
func (l *Loop) Run(ctx context.Context) error {
	interval, inventoryEvery := 60*time.Second, 15*time.Minute
	backoff := 5 * time.Second
	for {
		res, err := l.Once(ctx, inventoryEvery)
		if l.Updater != nil && !errors.Is(err, client.ErrNotEnrolled) {
			if herr := l.Updater.Health(err == nil); errors.Is(herr, update.ErrRestart) {
				return herr
			}
			if err == nil && res.Update != nil {
				if aerr := l.Updater.Apply(ctx, *res.Update); errors.Is(aerr, update.ErrRestart) {
					return aerr
				}
			}
		}
		wait := interval
		switch {
		case errors.Is(err, client.ErrNotEnrolled):
			return err
		case err != nil:
			l.Log.Warn("check-in failed; will retry", "err", err, "in", backoff)
			wait, backoff = backoff, min(backoff*2, 5*time.Minute)
		default:
			backoff = 5 * time.Second
			if res.CheckinInterval > 0 {
				interval = time.Duration(res.CheckinInterval) * time.Second
			}
			if res.InventoryInterval > 0 {
				inventoryEvery = time.Duration(res.InventoryInterval) * time.Second
			}
			wait = interval
			if l.soon {
				wait, l.soon = 2*time.Second, false // report command results promptly
			}
			l.Log.Info("checked in", "compliance", res.Compliance, "next_in", wait)
		}
		// ±10% jitter so a fleet doesn't check in in lockstep.
		wait = time.Duration(float64(wait) * (0.9 + 0.2*rand.Float64()))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

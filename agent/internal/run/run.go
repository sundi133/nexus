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
)

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

	lastInventory     [32]byte
	lastInventoryTime time.Time
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
	res, err := l.Client.Checkin(ctx, payload)
	if err == nil && sendInventory {
		l.lastInventory, l.lastInventoryTime = sum, time.Now()
	}
	if err == nil && l.OnCheckin != nil {
		l.OnCheckin(res)
	}
	return res, err
}

// Run checks in until ctx is cancelled or the server says the device was removed.
func (l *Loop) Run(ctx context.Context) error {
	interval, inventoryEvery := 60*time.Second, 15*time.Minute
	backoff := 5 * time.Second
	for {
		res, err := l.Once(ctx, inventoryEvery)
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

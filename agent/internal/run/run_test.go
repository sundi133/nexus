package run

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/votal-ai/nexus/agent/internal/client"
	"github.com/votal-ai/nexus/agent/internal/collect"
	"github.com/votal-ai/nexus/agent/internal/release"
	"github.com/votal-ai/nexus/agent/internal/update"
)

type fake struct {
	calls    []map[string]any
	failWith error
	offer    *release.Offer
}

func (f *fake) Checkin(_ context.Context, p any) (*client.CheckinResult, error) {
	f.calls = append(f.calls, p.(map[string]any))
	if f.failWith != nil {
		return nil, f.failWith
	}
	return &client.CheckinResult{CheckinInterval: 60, InventoryInterval: 900, Compliance: "compliant", Update: f.offer}, nil
}

func TestInventoryOnlyWhenChanged(t *testing.T) {
	f := &fake{}
	mem := uint64(8)
	l := &Loop{Client: f, Version: "t", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Collect: func(context.Context) collect.Snapshot {
		return collect.Snapshot{Inventory: collect.Inventory{MemoryBytes: mem}}
	}}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := l.Once(ctx, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	mem = 16
	_, _ = l.Once(ctx, time.Hour)
	has := func(i int) bool { _, ok := f.calls[i]["inventory"]; return ok }
	if !has(0) || has(1) || !has(2) {
		t.Fatalf("inventory sent pattern: %v %v %v", has(0), has(1), has(2))
	}
	if f.calls[0]["posture"] == nil || f.calls[0]["device"].(map[string]any)["agent_version"] != "t" {
		t.Fatal("posture and agent version must always be sent")
	}
}

func TestStopsWhenDeviceRemoved(t *testing.T) {
	f := &fake{failWith: client.ErrNotEnrolled}
	l := &Loop{Client: f, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Collect: func(context.Context) collect.Snapshot { return collect.Snapshot{} }}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := l.Run(ctx); !errors.Is(err, client.ErrNotEnrolled) {
		t.Fatalf("want ErrNotEnrolled, got %v", err)
	}
}

type fakeUpdater struct {
	result  *release.Result
	cleared int
	applied []string
	health  []bool
}

func (u *fakeUpdater) Apply(_ context.Context, o release.Offer) error {
	u.applied = append(u.applied, o.Version)
	return update.ErrRestart
}
func (u *fakeUpdater) Health(ok bool) error          { u.health = append(u.health, ok); return nil }
func (u *fakeUpdater) Result() *release.Result       { return u.result }
func (u *fakeUpdater) ClearResult(r *release.Result) { u.cleared++; u.result = nil }

func TestReportsUpdateResultsAndAppliesOffers(t *testing.T) {
	f := &fake{}
	u := &fakeUpdater{result: &release.Result{Version: "0.2.0", State: "rolled_back", Error: "boom"}}
	l := &Loop{Client: f, Version: "0.1.0", Updater: u, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Collect: func(context.Context) collect.Snapshot { return collect.Snapshot{} }}
	if _, err := l.Once(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if r, ok := f.calls[0]["update_result"].(*release.Result); !ok || r.State != "rolled_back" || u.cleared != 1 {
		t.Fatalf("update_result = %v, cleared %d", f.calls[0]["update_result"], u.cleared)
	}
	if _, err := l.Once(context.Background(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, sent := f.calls[1]["update_result"]; sent {
		t.Fatal("result reported twice")
	}

	f.offer = &release.Offer{Version: "0.3.0"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := l.Run(ctx); !errors.Is(err, update.ErrRestart) {
		t.Fatalf("Run = %v, want ErrRestart", err)
	}
	if len(u.applied) != 1 || u.applied[0] != "0.3.0" || len(u.health) != 1 || !u.health[0] {
		t.Fatalf("applied %v, health %v", u.applied, u.health)
	}
}

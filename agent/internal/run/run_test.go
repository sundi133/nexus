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
)

type fake struct {
	calls    []map[string]any
	failWith error
}

func (f *fake) Checkin(_ context.Context, p any) (*client.CheckinResult, error) {
	f.calls = append(f.calls, p.(map[string]any))
	if f.failWith != nil {
		return nil, f.failWith
	}
	return &client.CheckinResult{CheckinInterval: 60, InventoryInterval: 900, Compliance: "compliant"}, nil
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

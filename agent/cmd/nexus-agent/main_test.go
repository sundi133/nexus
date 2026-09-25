package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/votal-ai/nexus/agent/internal/collect"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/votal-ai/nexus/agent/internal/state"
)

func TestReadConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "enroll.conf")
	_ = os.WriteFile(p, []byte("# dropped by MDM\nserver = https://api.nexus.example.com\r\ntoken=nxe_abc\n"), 0o600)
	server, token, err := readConfig(p)
	if err != nil || server != "https://api.nexus.example.com" || token != "nxe_abc" {
		t.Fatalf("got %q %q %v", server, token, err)
	}
	_ = os.WriteFile(p, []byte("server=https://x\n"), 0o600)
	if _, _, err := readConfig(p); err == nil {
		t.Fatal("missing token accepted")
	}
}

// The MSI (or an MDM) writes enroll.conf into the state folder; the running
// service enrolls from it, retries while the server can't be reached, and
// deletes the file (it holds a secret).
func TestAwaitEnrollmentFromInstallerConfig(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "starting up", http.StatusServiceUnavailable)
			return
		}
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/agent/enroll" || body.Token != "nxe_msi" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"device_id": "dev-1", "organization": "Acme", "web_origin": "https://nexus.acme.com"})
	}))
	defer srv.Close()
	enrollRetry = 10 * time.Millisecond
	// Real collection shells out (PowerShell on Windows) and takes seconds: not what this tests.
	deviceSnapshot = func(context.Context) collect.Snapshot {
		var s collect.Snapshot
		s.Device.Hostname, s.Device.Platform = "test-host", "test"
		return s
	}
	store := state.Store{Dir: t.TempDir()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Nothing yet: waits (until cancelled) instead of failing.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := awaitEnrollment(ctx, store, log); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected to keep waiting, got %v", err)
	}

	// What Windows Installer's IniFile table writes: a section header and CRLFs.
	conf := store.EnrollConfig()
	if err := os.WriteFile(conf, []byte("[Nexus]\r\nserver="+srv.URL+"\r\ntoken=nxe_msi\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if err := awaitEnrollment(ctx2, store, log); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("expected a retry after the first failure, got %d calls", calls)
	}
	_, e, err := store.Load()
	if err != nil || e.DeviceID != "dev-1" || e.Organization != "Acme" {
		t.Fatalf("not enrolled: %+v %v", e, err)
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatal("enroll.conf should be deleted after use")
	}
	if fi, _ := os.Stat(store.Dir); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Fatalf("state folder is %v", fi.Mode().Perm())
	}
}

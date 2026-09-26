package state

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/votal-ai/nexus/agent/internal/identity"
)

func TestSaveLoadForget(t *testing.T) {
	s := Store{Dir: t.TempDir() + "/nexus"}
	if _, _, err := s.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("want ErrNotEnrolled, got %v", err)
	}
	k, _ := identity.Generate()
	if err := s.Save(k, Enrollment{Server: "https://api.example.com", DeviceID: "d1", Organization: "Acme"}); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(s.keyPath())
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("device key must be 0600, got %v", info.Mode().Perm())
		}
	}
	k2, e, err := s.Load()
	if err != nil || e.DeviceID != "d1" {
		t.Fatalf("load: %v %+v", err, e)
	}
	a, _ := k.PublicJWK()
	b, _ := k2.PublicJWK()
	if a != b {
		t.Fatal("key changed across save/load")
	}
	if err := s.Forget(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatal("forget did not remove the enrollment")
	}
}

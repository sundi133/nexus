// Package state persists the agent's identity: the device key and enrollment.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/votal-ai/nexus/agent/internal/identity"
)

type Enrollment struct {
	Server       string `json:"server"`
	DeviceID     string `json:"device_id"`
	Organization string `json:"organization"`
	// WebOrigin is the Nexus console origin; the loopback server attests only to it.
	WebOrigin string `json:"web_origin,omitempty"`
}

// DefaultDir is where a system-wide agent keeps its state.
func DefaultDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/Nexus"
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Nexus")
	default:
		return "/var/lib/nexus-agent"
	}
}

type Store struct{ Dir string }

func (s Store) keyPath() string   { return filepath.Join(s.Dir, "device.key") }
func (s Store) statePath() string { return filepath.Join(s.Dir, "enrollment.json") }

var ErrNotEnrolled = errors.New("this device is not enrolled; run `nexus-agent enroll` first")

func (s Store) Load() (*identity.Key, *Enrollment, error) {
	raw, err := os.ReadFile(s.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, nil, err
	}
	var e Enrollment
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, nil, fmt.Errorf("enrollment state is corrupt: %w", err)
	}
	keyPEM, err := os.ReadFile(s.keyPath())
	if err != nil {
		return nil, nil, fmt.Errorf("device key missing: %w", err)
	}
	k, err := identity.ParsePEM(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	return k, &e, nil
}

// Save writes key and enrollment atomically with owner-only permissions.
func (s Store) Save(k *identity.Key, e Enrollment) error {
	if err := s.Prepare(); err != nil {
		return err
	}
	keyPEM, err := k.MarshalPEM()
	if err != nil {
		return err
	}
	if err := writeAtomic(s.keyPath(), keyPEM); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(e, "", "  ")
	return writeAtomic(s.statePath(), data)
}

// Prepare creates the state folder if needed and restricts it to the system and administrators.
func (s Store) Prepare() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return secureDir(s.Dir)
}

// EnrollConfig is where an installer (MSI properties, MDM) leaves server= and
// token= for the agent to enroll itself; the agent deletes it after use.
func (s Store) EnrollConfig() string { return filepath.Join(s.Dir, "enroll.conf") }

// Forget removes the enrollment (after the server says the device was removed).
func (s Store) Forget() error {
	for _, p := range []string{s.statePath(), s.keyPath()} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Package collect gathers device facts. It reports raw facts only; the server
// decides compliance. Anything it can't determine with certainty is "unknown",
// never "on".
package collect

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

type Status string

const (
	On      Status = "on"
	Off     Status = "off"
	Unknown Status = "unknown"
)

type Fact struct {
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type ScreenLock struct {
	Status       Status `json:"status"`
	DelaySeconds *int   `json:"delay_seconds,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

type Posture struct {
	DiskEncryption  Fact       `json:"disk_encryption"`
	Firewall        Fact       `json:"firewall"`
	ScreenLock      ScreenLock `json:"screen_lock"`
	SystemIntegrity Fact       `json:"system_integrity"`
}

type LocalUser struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

type Inventory struct {
	CPU           string       `json:"cpu,omitempty"`
	MemoryBytes   uint64       `json:"memory_bytes,omitempty"`
	LocalUsers    []LocalUser  `json:"local_users,omitempty"`
	ConsoleUser   string       `json:"console_user,omitempty"`
	UptimeSeconds int64        `json:"uptime_seconds,omitempty"`
	AI            *AIInventory `json:"ai,omitempty"`
}

type Device struct {
	Hostname  string `json:"hostname"`
	Platform  string `json:"platform"`
	OSName    string `json:"os_name"`
	OSVersion string `json:"os_version"`
	OSBuild   string `json:"os_build"`
	Arch      string `json:"arch"`
	Model     string `json:"model"`
	Serial    string `json:"serial"`
}

type Snapshot struct {
	Device    Device    `json:"device"`
	Posture   Posture   `json:"posture"`
	Inventory Inventory `json:"inventory"`
}

// Collect gathers a full snapshot for the current OS (see collect_<os>.go).
func Collect(ctx context.Context) Snapshot {
	s := collect(ctx)
	s.Inventory.AI = DiscoverAI(aiEnv())
	return s
}

// run executes a command with a timeout and returns trimmed stdout+stderr.
// Many admin tools print their answer on stderr, so both are captured.
func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func unknown(detail string) Fact { return Fact{Status: Unknown, Detail: detail} }

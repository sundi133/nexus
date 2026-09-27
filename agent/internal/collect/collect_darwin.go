//go:build darwin

package collect

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func collect(ctx context.Context) Snapshot {
	var s Snapshot
	s.Device.Platform = "macos"
	s.Device.OSName = "macOS"
	s.Device.Arch = runtime.GOARCH
	s.Device.Hostname, _ = os.Hostname()
	if name, err := run(ctx, "scutil", "--get", "ComputerName"); err == nil && name != "" {
		s.Device.Hostname = name
	}
	s.Device.OSVersion, _ = run(ctx, "sw_vers", "-productVersion")
	s.Device.OSBuild, _ = run(ctx, "sw_vers", "-buildVersion")
	s.Device.Model, _ = run(ctx, "sysctl", "-n", "hw.model")
	if out, err := run(ctx, "ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"); err == nil {
		s.Device.Serial = ParseIoregSerial(out)
	}

	if out, err := run(ctx, "fdesetup", "status"); err == nil {
		s.Posture.DiskEncryption = ParseFileVault(out)
	} else {
		s.Posture.DiskEncryption = unknown("fdesetup failed")
	}
	if out, err := run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err == nil {
		s.Posture.Firewall = ParseMacFirewall(out)
	} else {
		s.Posture.Firewall = unknown("socketfilterfw failed")
	}
	if out, err := run(ctx, "csrutil", "status"); err == nil {
		s.Posture.SystemIntegrity = ParseCsrutil(out)
	} else {
		s.Posture.SystemIntegrity = unknown("csrutil failed")
	}
	// sysadminctl prints on stderr and may exit non-zero; parse whatever it said.
	out, _ := run(ctx, "sysadminctl", "-screenLock", "status")
	s.Posture.ScreenLock = ParseMacScreenLock(out)

	s.Inventory.CPU, _ = run(ctx, "sysctl", "-n", "machdep.cpu.brand_string")
	if mem, err := run(ctx, "sysctl", "-n", "hw.memsize"); err == nil {
		s.Inventory.MemoryBytes, _ = strconv.ParseUint(mem, 10, 64)
	}
	if bt, err := run(ctx, "sysctl", "-n", "kern.boottime"); err == nil {
		if sec := ParseBoottime(bt); sec > 0 {
			s.Inventory.UptimeSeconds = time.Now().Unix() - sec
		}
	}
	if u, err := run(ctx, "stat", "-f", "%Su", "/dev/console"); err == nil && u != "root" {
		s.Inventory.ConsoleUser = u
	}
	if out, err := run(ctx, "dscl", ".", "-read", "/Groups/admin", "GroupMembership"); err == nil {
		for _, name := range ParseDsclGroup(out) {
			if name != "root" && !strings.HasPrefix(name, "_") {
				s.Inventory.LocalUsers = append(s.Inventory.LocalUsers, LocalUser{Name: name, Admin: true})
			}
		}
	}
	return s
}

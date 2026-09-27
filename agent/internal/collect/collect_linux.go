//go:build linux

package collect

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func collect(ctx context.Context) Snapshot {
	var s Snapshot
	s.Device.Platform = "linux"
	s.Device.Arch = runtime.GOARCH
	s.Device.Hostname, _ = os.Hostname()
	osr := ParseOSRelease(readTrim("/etc/os-release"))
	s.Device.OSName = osr["NAME"]
	s.Device.OSVersion = osr["VERSION_ID"]
	s.Device.OSBuild, _ = run(ctx, "uname", "-r")
	s.Device.Model = readTrim("/sys/class/dmi/id/product_name")
	s.Device.Serial = readTrim("/sys/class/dmi/id/product_serial") // root only

	if src, err := run(ctx, "findmnt", "-no", "SOURCE", "/"); err == nil && src != "" {
		out, _ := run(ctx, "lsblk", "-rsno", "TYPE", src)
		s.Posture.DiskEncryption = ParseLsblkTypes(out)
	} else {
		s.Posture.DiskEncryption = unknown("could not find the root device")
	}
	s.Posture.Firewall = unknown("no supported firewall found (ufw, firewalld)")
	if out, err := run(ctx, "ufw", "status"); err == nil {
		if f := ParseUfw(out); f.Status != Unknown {
			s.Posture.Firewall = f
		}
	}
	if s.Posture.Firewall.Status == Unknown {
		if out, err := run(ctx, "firewall-cmd", "--state"); err == nil && out == "running" {
			s.Posture.Firewall = Fact{Status: On, Detail: "firewalld"}
		}
	}
	out, _ := run(ctx, "mokutil", "--sb-state")
	s.Posture.SystemIntegrity = ParseMokutil(out)
	// Screen lock lives in each desktop user's session settings; not readable from a system service yet.
	s.Posture.ScreenLock = ScreenLock{Status: Unknown, Detail: "screen lock is a per-user desktop setting"}

	if mem := readTrim("/proc/meminfo"); mem != "" {
		for _, line := range strings.Split(mem, "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
				kb, _ := strconv.ParseUint(f[1], 10, 64)
				s.Inventory.MemoryBytes = kb * 1024
			}
		}
	}
	if up := strings.Fields(readTrim("/proc/uptime")); len(up) > 0 {
		f, _ := strconv.ParseFloat(up[0], 64)
		s.Inventory.UptimeSeconds = int64(f)
	}
	return s
}

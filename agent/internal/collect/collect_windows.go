//go:build windows

package collect

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
)

func powershell(ctx context.Context, script string) (string, error) {
	return run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}

func collect(ctx context.Context) Snapshot {
	var s Snapshot
	s.Device.Platform = "windows"
	s.Device.Arch = runtime.GOARCH
	s.Device.Hostname, _ = os.Hostname()
	if out, err := run(ctx, "reg", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`); err == nil {
		s.Device.OSName, s.Device.OSVersion, s.Device.OSBuild = WindowsVersion(ParseRegQuery(out))
	}
	s.Device.Serial, _ = powershell(ctx, "(Get-CimInstance Win32_BIOS).SerialNumber")
	s.Device.Model, _ = powershell(ctx, "(Get-CimInstance Win32_ComputerSystem).Model")

	out, _ := powershell(ctx, "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus")
	s.Posture.DiskEncryption = ParseBitLocker(out)
	if out, err := run(ctx, "netsh", "advfirewall", "show", "allprofiles", "state"); err == nil {
		s.Posture.Firewall = ParseNetshFirewall(out)
	} else {
		s.Posture.Firewall = unknown("netsh failed")
	}
	out, _ = powershell(ctx, "Confirm-SecureBootUEFI")
	s.Posture.SystemIntegrity = ParseSecureBoot(out)

	// Machine inactivity limit (Group Policy "Interactive logon: Machine inactivity limit").
	s.Posture.ScreenLock = ScreenLock{Status: Unknown, Detail: "no machine inactivity limit policy set"}
	if out, err := run(ctx, "reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "InactivityTimeoutSecs"); err == nil {
		if v, ok := ParseRegQuery(out)["InactivityTimeoutSecs"]; ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				s.Posture.ScreenLock = ScreenLock{Status: On, DelaySeconds: &n}
			} else if n == 0 {
				s.Posture.ScreenLock = ScreenLock{Status: Off}
			}
		}
	}

	s.Inventory.CPU, _ = powershell(ctx, "(Get-CimInstance Win32_Processor | Select-Object -First 1).Name")
	if mem, err := powershell(ctx, "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"); err == nil {
		s.Inventory.MemoryBytes, _ = strconv.ParseUint(strings.TrimSpace(mem), 10, 64)
	}
	if u, err := powershell(ctx, "(Get-CimInstance Win32_ComputerSystem).UserName"); err == nil {
		s.Inventory.ConsoleUser = u
	}
	return s
}

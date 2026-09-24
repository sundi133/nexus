package collect

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"
)

// ---- macOS ------------------------------------------------------------------------

// ParseFileVault reads `fdesetup status`. Encryption still in progress doesn't protect the disk yet.
func ParseFileVault(out string) Fact {
	switch {
	case strings.Contains(out, "FileVault is On") && strings.Contains(out, "Encryption in progress"):
		return Fact{Status: Off, Detail: "FileVault encryption is still in progress"}
	case strings.Contains(out, "FileVault is On"):
		return Fact{Status: On}
	case strings.Contains(out, "FileVault is Off"):
		return Fact{Status: Off}
	}
	return unknown("unrecognized fdesetup output")
}

// ParseMacFirewall reads `socketfilterfw --getglobalstate` ("Firewall is enabled. (State = 1)").
func ParseMacFirewall(out string) Fact {
	switch {
	case strings.Contains(out, "enabled"):
		return Fact{Status: On}
	case strings.Contains(out, "disabled"):
		return Fact{Status: Off}
	}
	return unknown("unrecognized socketfilterfw output")
}

// ParseCsrutil reads `csrutil status`. A custom (partially disabled) configuration is not "on".
func ParseCsrutil(out string) Fact {
	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "status: enabled"):
		return Fact{Status: On}
	case strings.Contains(lower, "status: disabled"):
		return Fact{Status: Off}
	case strings.Contains(lower, "custom configuration"):
		return Fact{Status: Off, Detail: "System Integrity Protection is partially disabled (custom configuration)"}
	}
	return unknown("unrecognized csrutil output")
}

var screenLockDelay = regexp.MustCompile(`screenLock delay is (\d+) seconds`)

// ParseMacScreenLock reads `sysadminctl -screenLock status` (printed on stderr).
func ParseMacScreenLock(out string) ScreenLock {
	switch {
	case strings.Contains(out, "screenLock delay is immediate"):
		zero := 0
		return ScreenLock{Status: On, DelaySeconds: &zero}
	case screenLockDelay.MatchString(out):
		n, _ := strconv.Atoi(screenLockDelay.FindStringSubmatch(out)[1])
		return ScreenLock{Status: On, DelaySeconds: &n}
	case strings.Contains(out, "screenLock is off"):
		return ScreenLock{Status: Off}
	}
	return ScreenLock{Status: Unknown, Detail: "screen lock setting not readable from this context"}
}

var ioregSerial = regexp.MustCompile(`"IOPlatformSerialNumber" = "([^"]+)"`)

func ParseIoregSerial(out string) string {
	if m := ioregSerial.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// ParseDsclGroup reads `dscl . -read /Groups/admin GroupMembership`.
func ParseDsclGroup(out string) []string {
	_, after, ok := strings.Cut(out, "GroupMembership:")
	if !ok {
		return nil
	}
	return strings.Fields(after)
}

var boottime = regexp.MustCompile(`sec = (\d+)`)

// ParseBoottime reads `sysctl -n kern.boottime` ("{ sec = 1727000000, usec = 0 } ...").
func ParseBoottime(out string) int64 {
	if m := boottime.FindStringSubmatch(out); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n
	}
	return 0
}

// ---- Windows --------------------------------------------------------------------------

// ParseBitLocker reads `(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus`.
func ParseBitLocker(out string) Fact {
	switch strings.TrimSpace(out) {
	case "On":
		return Fact{Status: On}
	case "Off":
		return Fact{Status: Off}
	}
	return unknown("BitLocker status not readable (requires administrator)")
}

// ParseNetshFirewall reads `netsh advfirewall show allprofiles state`: on only if every profile is ON.
func ParseNetshFirewall(out string) Fact {
	var on, total int
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.EqualFold(f[0], "State") {
			total++
			if strings.EqualFold(f[1], "ON") {
				on++
			}
		}
	}
	switch {
	case total == 0:
		return unknown("unrecognized netsh output")
	case on == total:
		return Fact{Status: On}
	}
	return Fact{Status: Off, Detail: strconv.Itoa(total-on) + " of " + strconv.Itoa(total) + " firewall profiles are off"}
}

// ParseSecureBoot reads `Confirm-SecureBootUEFI` (True/False; errors on legacy BIOS).
func ParseSecureBoot(out string) Fact {
	switch strings.TrimSpace(out) {
	case "True":
		return Fact{Status: On}
	case "False":
		return Fact{Status: Off}
	}
	return unknown("Secure Boot state not readable")
}

var regLine = regexp.MustCompile(`^\s+(\S+)\s+REG_\w+\s+(.*)$`)

// ParseRegQuery reads `reg query <key>` output into name → value (DWORDs as decimal strings).
func ParseRegQuery(out string) map[string]string {
	vals := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		m := regLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		v := strings.TrimSpace(m[2])
		if strings.HasPrefix(v, "0x") {
			if n, err := strconv.ParseUint(v[2:], 16, 64); err == nil {
				v = strconv.FormatUint(n, 10)
			}
		}
		vals[m[1]] = v
	}
	return vals
}

// WindowsVersion turns CurrentVersion registry values into ("Windows 11 Pro", "10.0.22631", "22631.4460").
func WindowsVersion(v map[string]string) (name, version, build string) {
	b, _ := strconv.Atoi(v["CurrentBuildNumber"])
	name = v["ProductName"]
	// Windows 11 still reports "Windows 10" in ProductName; the build number is authoritative.
	if b >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	if v["CurrentMajorVersionNumber"] != "" {
		version = v["CurrentMajorVersionNumber"] + "." + v["CurrentMinorVersionNumber"] + "." + v["CurrentBuildNumber"]
	}
	build = v["CurrentBuildNumber"]
	if v["UBR"] != "" {
		build += "." + v["UBR"]
	}
	return
}

// ---- Linux ------------------------------------------------------------------------------

func ParseOSRelease(content string) map[string]string {
	vals := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			vals[k] = strings.Trim(v, `"'`)
		}
	}
	return vals
}

// ParseLsblkTypes reads `lsblk -rsno TYPE <root device>` (the root's ancestry): any "crypt" means LUKS.
func ParseLsblkTypes(out string) Fact {
	if strings.TrimSpace(out) == "" {
		return unknown("could not inspect the root device")
	}
	for _, t := range strings.Fields(out) {
		if t == "crypt" {
			return Fact{Status: On}
		}
	}
	return Fact{Status: Off}
}

func ParseUfw(out string) Fact {
	switch {
	case strings.Contains(out, "Status: active"):
		return Fact{Status: On, Detail: "ufw"}
	case strings.Contains(out, "Status: inactive"):
		return Fact{Status: Off, Detail: "ufw"}
	}
	return unknown("")
}

func ParseMokutil(out string) Fact {
	switch {
	case strings.Contains(out, "SecureBoot enabled"):
		return Fact{Status: On}
	case strings.Contains(out, "SecureBoot disabled"):
		return Fact{Status: Off}
	}
	return unknown("Secure Boot state not readable")
}

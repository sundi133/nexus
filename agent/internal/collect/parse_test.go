package collect

import "testing"

func TestMacParsers(t *testing.T) {
	cases := []struct {
		name string
		got  Status
		want Status
	}{
		{"fv on", ParseFileVault("FileVault is On.").Status, On},
		{"fv off", ParseFileVault("FileVault is Off.").Status, Off},
		{"fv in progress", ParseFileVault("FileVault is On.\nEncryption in progress: Percent completed = 42.1").Status, Off},
		{"fv garbage", ParseFileVault("").Status, Unknown},
		{"fw on", ParseMacFirewall("Firewall is enabled. (State = 1)").Status, On},
		{"fw block all", ParseMacFirewall("Firewall is enabled. (State = 2)").Status, On},
		{"fw off", ParseMacFirewall("Firewall is disabled. (State = 0)").Status, Off},
		{"sip on", ParseCsrutil("System Integrity Protection status: enabled.").Status, On},
		{"sip off", ParseCsrutil("System Integrity Protection status: disabled.").Status, Off},
		{"sip custom", ParseCsrutil("System Integrity Protection status: unknown (Custom Configuration).").Status, Off},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %s want %s", c.name, c.got, c.want)
		}
	}
	sl := ParseMacScreenLock("2026-09-24 10:00:00.000 sysadminctl[811:5012] screenLock delay is 300 seconds")
	if sl.Status != On || sl.DelaySeconds == nil || *sl.DelaySeconds != 300 {
		t.Errorf("screen lock delay: %+v", sl)
	}
	if sl := ParseMacScreenLock("sysadminctl[1:2] screenLock delay is immediate"); sl.Status != On || *sl.DelaySeconds != 0 {
		t.Errorf("immediate: %+v", sl)
	}
	if sl := ParseMacScreenLock("sysadminctl[1:2] screenLock is off"); sl.Status != Off {
		t.Errorf("off: %+v", sl)
	}
	if sl := ParseMacScreenLock("### Error: requires user context"); sl.Status != Unknown {
		t.Errorf("unreadable must be unknown: %+v", sl)
	}
	if s := ParseIoregSerial(`    | "IOPlatformSerialNumber" = "C02ABC123XYZ"`); s != "C02ABC123XYZ" {
		t.Errorf("serial %q", s)
	}
	if u := ParseDsclGroup("GroupMembership: root priya"); len(u) != 2 || u[1] != "priya" {
		t.Errorf("admins %v", u)
	}
	if b := ParseBoottime("{ sec = 1790200000, usec = 123 } Wed Sep 23"); b != 1790200000 {
		t.Errorf("boottime %d", b)
	}
}

func TestWindowsParsers(t *testing.T) {
	if ParseBitLocker("On\r\n").Status != On || ParseBitLocker("Off").Status != Off || ParseBitLocker("Access denied").Status != Unknown {
		t.Error("bitlocker")
	}
	netsh := "Domain Profile Settings:\r\n----------------------------------------------------------------------\r\nState                                 ON\r\n\r\nPrivate Profile Settings:\r\n----------------------------------------------------------------------\r\nState                                 ON\r\n\r\nPublic Profile Settings:\r\n----------------------------------------------------------------------\r\nState                                 OFF\r\nOk.\r\n"
	if f := ParseNetshFirewall(netsh); f.Status != Off || f.Detail != "1 of 3 firewall profiles are off" {
		t.Errorf("netsh: %+v", f)
	}
	if ParseSecureBoot("True").Status != On || ParseSecureBoot("Cmdlet not supported on this platform").Status != Unknown {
		t.Error("secure boot")
	}
	reg := "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n    ProductName    REG_SZ    Windows 10 Pro\r\n    DisplayVersion    REG_SZ    23H2\r\n    CurrentMajorVersionNumber    REG_DWORD    0xa\r\n    CurrentMinorVersionNumber    REG_DWORD    0x0\r\n    CurrentBuildNumber    REG_SZ    22631\r\n    UBR    REG_DWORD    0x116c\r\n"
	name, version, build := WindowsVersion(ParseRegQuery(reg))
	if name != "Windows 11 Pro" || version != "10.0.22631" || build != "22631.4460" {
		t.Errorf("windows version: %q %q %q", name, version, build)
	}
}

func TestLinuxParsers(t *testing.T) {
	osr := ParseOSRelease("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n")
	if osr["NAME"] != "Ubuntu" || osr["VERSION_ID"] != "24.04" {
		t.Errorf("os-release %v", osr)
	}
	if ParseLsblkTypes("lvm\ncrypt\npart\ndisk\n").Status != On || ParseLsblkTypes("part\ndisk\n").Status != Off || ParseLsblkTypes("").Status != Unknown {
		t.Error("lsblk")
	}
	if ParseUfw("Status: active\n\nTo Action From").Status != On || ParseUfw("Status: inactive").Status != Off {
		t.Error("ufw")
	}
	if ParseMokutil("SecureBoot enabled").Status != On || ParseMokutil("EFI variables are not supported on this system").Status != Unknown {
		t.Error("mokutil")
	}
}

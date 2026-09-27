package updates

import (
	"context"
	"strings"
	"testing"
)

func TestParseSoftwareUpdate(t *testing.T) {
	out := `Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sonoma 14.6.1-23G93
	Title: macOS Sonoma 14.6.1, Version: 14.6.1, Size: 1024000KiB, Recommended: YES, Action: restart,
* Label: Safari17.6SonomaAuto-17.6
	Title: Safari, Version: 17.6, Size: 150000KiB, Recommended: YES,
`
	u := ParseSoftwareUpdate(out, "14")
	if len(u) != 2 || u[0].Name != "macOS Sonoma 14.6.1" || u[0].Version != "14.6.1" || !u[0].Restart || u[1].Restart || !u[1].Security || u[0].Label != "macOS Sonoma 14.6.1-23G93" {
		t.Fatalf("%+v", u)
	}
	if len(ParseSoftwareUpdate("Software Update Tool\n\nNo new software available.", "14")) != 0 {
		t.Fatal("found updates in nothing")
	}
}

func TestParseApt(t *testing.T) {
	out := `Listing... Done
openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
curl/jammy-updates 7.81.0-1ubuntu1.17 amd64 [upgradable from: 7.81.0-1ubuntu1.16]
linux-image-generic/jammy-security 5.15.0.119.119 amd64 [upgradable from: 5.15.0.117.117]`
	u := ParseAptUpgradable(out)
	if len(u) != 3 || !u[0].Security || u[1].Security || !u[2].Restart || u[0].Version != "3.0.2-0ubuntu1.18" {
		t.Fatalf("%+v", u)
	}
}

func TestParseDnf(t *testing.T) {
	sec := ParseDnfSecurity(`FEDORA-2024-abc Important/Sec. openssl-libs-3.1.4-3.fc39.x86_64
FEDORA-2024-def Moderate/Sec.  kernel-6.9.7-100.fc39.x86_64`)
	if !sec["openssl-libs"] || !sec["kernel"] {
		t.Fatalf("%v", sec)
	}
	u := ParseDnfCheckUpdate(`Last metadata expiration check: 0:10:00 ago.

openssl-libs.x86_64                1:3.1.4-3.fc39                updates
kernel.x86_64                      6.9.7-100.fc39                updates
vim-minimal.x86_64                 2:9.1.393-1.fc39              updates`, sec)
	if len(u) != 3 || !u[0].Security || !u[1].Restart || u[2].Security {
		t.Fatalf("%+v", u)
	}
}

func TestParseWindows(t *testing.T) {
	u, err := ParseWindowsUpdates(`[{"Title":"2024-09 Cumulative Update for Windows 11 (KB5043076)","Security":true,"Restart":true},{"Title":"Microsoft Defender Antivirus definition update","Security":false,"Restart":false}]`)
	if err != nil || len(u) != 2 || !u[0].Security || !u[0].Restart {
		t.Fatalf("%+v %v", u, err)
	}
	one, _ := ParseWindowsUpdates(`{"Title":"KB1","Security":true,"Restart":false}`)
	if len(one) != 1 {
		t.Fatal("single object")
	}
	none, _ := ParseWindowsUpdates("")
	if len(none) != 0 {
		t.Fatal("empty")
	}
}

func fakeRun(answers map[string]string, ran *[]string) Run {
	return func(_ context.Context, name string, args ...string) (string, error) {
		cmd := strings.Join(append([]string{name}, args...), " ")
		*ran = append(*ran, cmd)
		for prefix, out := range answers {
			if strings.HasPrefix(cmd, prefix) {
				return out, nil
			}
		}
		return "", nil
	}
}

func TestInstallSecurityOnlyOnApt(t *testing.T) {
	var ran []string
	run := fakeRun(map[string]string{"apt list": "openssl/jammy-security 3.0.2 amd64 [upgradable from: 3.0.1]\ncurl/jammy-updates 7.81 amd64 [upgradable from: 7.80]"}, &ran)
	has := func(n string) bool { return n == "apt-get" }
	msg, err := Install(context.Background(), "linux", run, has, true)
	if err != nil || msg != "upgraded 1 security packages" {
		t.Fatalf("%q %v", msg, err)
	}
	last := ran[len(ran)-1]
	if !strings.HasSuffix(last, "--only-upgrade install openssl") {
		t.Fatalf("installed %q", last)
	}
}

// As seen on a real Mac on 14.x: the next major macOS is listed beside the security update.
const macWithUpgrade = `Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sonoma 14.8.9-23J631
	Title: macOS Sonoma 14.8.9, Version: 14.8.9, Size: 2226816KiB, Recommended: YES, Action: restart,
* Label: macOS 27-26A428
	Title: macOS 27, Version: 27, Size: 14468835KiB, Recommended: YES, Action: restart,
`

func TestMacMajorUpgradeIsReportedNotInstalled(t *testing.T) {
	u := ParseSoftwareUpdate(macWithUpgrade, "14")
	if len(u) != 2 || !u[0].Security || u[0].Upgrade || u[1].Security || !u[1].Upgrade {
		t.Fatalf("%+v", u)
	}
	for _, sec := range []bool{true, false} {
		var ran []string
		msg, err := Install(context.Background(), "darwin", fakeRun(map[string]string{"sw_vers": "14.8.1\n", "softwareupdate -l": macWithUpgrade}, &ran), nil, sec)
		if err != nil || ran[len(ran)-1] != "softwareupdate --install macOS Sonoma 14.8.9-23J631 --agree-to-license" {
			t.Fatalf("%v: ran %q (%q, %v)", sec, ran, msg, err)
		}
	}
	var ran []string
	msg, _ := Install(context.Background(), "darwin", fakeRun(map[string]string{"sw_vers": "14.8.9", "softwareupdate -l": "* Label: macOS 27-26A428\n\tTitle: macOS 27, Version: 27, Size: 1KiB, Recommended: YES, Action: restart,\n"}, &ran), nil, false)
	if msg != "no updates to install" || len(ran) != 2 {
		t.Fatalf("%q %q", msg, ran)
	}
}

func TestWindowsFeatureUpdatesAreUpgrades(t *testing.T) {
	u, err := ParseWindowsUpdates(`[{"Title":"2026-09 Cumulative Update","Security":true,"Restart":true,"Upgrade":false},{"Title":"Windows 11, version 25H2","Security":true,"Restart":true,"Upgrade":true}]`)
	if err != nil || !u[0].Security || u[1].Security || !u[1].Upgrade {
		t.Fatalf("%+v %v", u, err)
	}
	if !strings.Contains(winInstall, "'Upgrades' }) { continue }") {
		t.Fatal("the install script must skip feature upgrades")
	}
}

func TestInstallCommandsPerOS(t *testing.T) {
	for _, tc := range []struct {
		goos, has, want string
		sec             bool
	}{
		{"linux", "dnf", "dnf -y -q upgrade --security", true},
		{"linux", "apt-get", "apt-get -y -q -o Dpkg::Options::=--force-confold upgrade", false},
	} {
		var ran []string
		_, _ = Install(context.Background(), tc.goos, fakeRun(nil, &ran), func(n string) bool { return n == tc.has }, tc.sec)
		if len(ran) == 0 || ran[len(ran)-1] != tc.want {
			t.Errorf("%s/%v: ran %q, want %q", tc.goos, tc.sec, ran, tc.want)
		}
	}
	var ran []string
	_, _ = Install(context.Background(), "windows", fakeRun(nil, &ran), nil, true)
	if !strings.Contains(ran[0], "$true") || strings.Contains(ran[0], "$SECURITY_ONLY") {
		t.Fatalf("windows script: %s", ran[0])
	}
}

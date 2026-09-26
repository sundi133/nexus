package service

import (
	"encoding/xml"
	"io"
	"os"
	"strings"
	"testing"
)

func TestLaunchdPlistIsValidXMLAndKeepsAlive(t *testing.T) {
	p := LaunchdPlist("/Library/Application Support/Nexus/bin/nexus-agent", "/Library/Application Support/Nexus", "/Library/Logs/Nexus/agent.log")
	d := xml.NewDecoder(strings.NewReader(p))
	for {
		_, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid XML: %v", err)
		}
	}
	for _, want := range []string{"<string>ai.votal.nexus-agent</string>", "<key>KeepAlive</key><true/>", "<string>run</string>", "<string>/Library/Application Support/Nexus/bin/nexus-agent</string>"} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %s", want)
		}
	}
	if strings.Contains(LaunchdPlist("/a&b<c", "/s", "/l"), "a&b<c") {
		t.Error("plist values not escaped")
	}
}

func TestSystemdUnitRestartsAndQuotes(t *testing.T) {
	u := SystemdUnit("/opt/nexus/bin/nexus-agent", "/var/lib/nexus agent")
	for _, want := range []string{`ExecStart="/opt/nexus/bin/nexus-agent" run --state-dir "/var/lib/nexus agent"`, "Restart=always", "WantedBy=multi-user.target"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q:\n%s", want, u)
		}
	}
}

// The unit the Linux packages ship must be the one `nexus-agent install` writes.
func TestPackagedUnitMatches(t *testing.T) {
	shipped, err := os.ReadFile("../../packaging/linux/nexus-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	// A checkout on Windows may turn LF into CRLF; the file ships with LF (.gitattributes).
	if want := SystemdUnit("/opt/nexus/bin/nexus-agent", "/var/lib/nexus-agent"); strings.ReplaceAll(string(shipped), "\r\n", "\n") != want {
		t.Fatalf("packaging/linux/nexus-agent.service differs from SystemdUnit():\n%s", want)
	}
}

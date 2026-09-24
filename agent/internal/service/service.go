// Package service installs the agent as a system service that starts at boot
// and is restarted if it exits (which is also how self-updates take effect
// on Windows): launchd on macOS, systemd on Linux, the SCM on Windows.
package service

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	Label       = "ai.votal.nexus-agent" // launchd
	UnitName    = "nexus-agent.service"  // systemd
	WindowsName = "NexusAgent"
)

// XML-escape for the plist.
func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// LaunchdPlist runs the agent at boot and restarts it whenever it exits.
func LaunchdPlist(bin, stateDir, logFile string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
    <string>--state-dir</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, Label, esc(bin), esc(stateDir), esc(logFile), esc(logFile))
}

// systemd quoting: wrap in double quotes, escaping backslashes and quotes.
func sdQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// SystemdUnit runs the agent at boot and restarts it whenever it exits.
func SystemdUnit(bin, stateDir string) string {
	return fmt.Sprintf(`[Unit]
Description=Votal Nexus device agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run --state-dir %s
Restart=always
RestartSec=5
# The agent reads system security settings, so it runs as root, with the rest locked down.
NoNewPrivileges=true
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`, sdQuote(bin), sdQuote(stateDir))
}

// CopyExecutable installs the running binary at dst (atomically), unless it's already there.
func CopyExecutable(dst string) error {
	src, err := os.Executable()
	if err != nil {
		return err
	}
	if src, err = filepath.EvalSymlinks(src); err != nil {
		return err
	}
	if abs, _ := filepath.Abs(dst); abs == src {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".installing"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

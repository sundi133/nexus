package service

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	InstallDir = "/Library/Application Support/Nexus/bin"
	BinName    = "nexus-agent"
	plistPath  = "/Library/LaunchDaemons/" + Label + ".plist"
	logFile    = "/Library/Logs/Nexus/agent.log"
)

func Install(bin, stateDir string) error {
	if err := os.MkdirAll("/Library/Logs/Nexus", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(LaunchdPlist(bin, stateDir, logFile)), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", "system/"+Label).Run() // reinstall: stop the old one first
	if out, err := exec.Command("launchctl", "bootstrap", "system", plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %v: %s", err, out)
	}
	return nil
}

func Uninstall() error {
	_ = exec.Command("launchctl", "bootout", "system/"+Label).Run()
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func Describe() string { return fmt.Sprintf("launchd daemon %s (logs: %s)", Label, logFile) }

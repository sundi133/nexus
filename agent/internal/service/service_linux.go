package service

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	InstallDir = "/opt/nexus/bin"
	BinName    = "nexus-agent"
	unitPath   = "/etc/systemd/system/" + UnitName
)

func systemctl(args ...string) error {
	if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %v: %v: %s", args, err, out)
	}
	return nil
}

func Install(bin, stateDir string) error {
	if err := os.WriteFile(unitPath, []byte(SystemdUnit(bin, stateDir)), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", UnitName); err != nil {
		return err
	}
	return systemctl("restart", UnitName)
}

func Uninstall() error {
	_ = systemctl("disable", "--now", UnitName)
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return systemctl("daemon-reload")
}

func Describe() string { return "systemd unit " + UnitName + " (logs: journalctl -u nexus-agent)" }

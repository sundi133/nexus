//go:build !windows

package command

import (
	"os/exec"
	"syscall"
)

// setProcessGroup runs the script in its own process group, so a timeout kills everything it started.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

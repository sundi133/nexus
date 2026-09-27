//go:build !windows

package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// restart replaces this process with the binary now on disk (same arguments),
// so an update or rollback takes effect whether or not a service manager runs us.
func restart(log *slog.Logger) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	// os.Executable may point at the renamed old file (".previous"); run the real path.
	if filepath.Ext(exe) == ".previous" || filepath.Ext(exe) == ".failed" {
		exe = exe[:len(exe)-len(filepath.Ext(exe))]
	}
	log.Info("restarting", "exe", exe)
	return syscall.Exec(exe, os.Args, os.Environ())
}

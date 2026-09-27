//go:build windows

package main

import (
	"log/slog"
	"os"
)

// On Windows a running binary can't replace its own process; exit and let the
// service's recovery settings (restart on failure) start the new binary.
func restart(log *slog.Logger) error {
	log.Info("exiting so the service manager starts the updated agent")
	os.Exit(75)
	return nil
}

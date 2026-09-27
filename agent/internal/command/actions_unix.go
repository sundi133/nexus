//go:build !windows

package command

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
)

func run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", &execError{cmd: name, out: strings.TrimSpace(string(out)), err: err}
	}
	return strings.TrimSpace(string(out)), nil
}

// Actions are the executors for this OS.
func Actions() map[string]Executor {
	return map[string]Executor{
		"refresh": func(context.Context) (string, error) { return "Reported", nil },
		"restart": func(ctx context.Context) (string, error) {
			// A minute's notice, so the result reaches Nexus before the device goes down.
			if _, err := run(ctx, "shutdown", "-r", "+1"); err != nil {
				return "", err
			}
			return "Restarting in 1 minute", nil
		},
		"lock": func(ctx context.Context) (string, error) {
			if runtime.GOOS == "darwin" {
				// Sleeping the display locks the Mac when a password is required after sleep (the screen lock policy).
				if _, err := run(ctx, "pmset", "displaysleepnow"); err != nil {
					return "", err
				}
				return "Display put to sleep (locks when a password is required on wake)", nil
			}
			if _, err := run(ctx, "loginctl", "lock-sessions"); err != nil {
				return "", err
			}
			return "Sessions locked", nil
		},
	}
}

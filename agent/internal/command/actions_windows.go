//go:build windows

package command

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

var (
	wtsapi                = windows.NewLazySystemDLL("wtsapi32.dll")
	procDisconnectSession = wtsapi.NewProc("WTSDisconnectSession")
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
			if _, err := run(ctx, "shutdown", "/r", "/t", "60", "/c", "Your IT team restarted this device from Nexus."); err != nil {
				return "", err
			}
			return "Restarting in 1 minute", nil
		},
		"lock": func(context.Context) (string, error) {
			// The service runs as SYSTEM, outside the user's session: disconnecting the
			// console session shows the lock screen, and nothing the user had open is lost.
			session := windows.WTSGetActiveConsoleSessionId()
			if session == 0xFFFFFFFF {
				return "No one is signed in at the console", nil
			}
			if r, _, err := procDisconnectSession.Call(0, uintptr(session), 0); r == 0 {
				return "", errors.New("couldn't lock the session: " + err.Error())
			}
			return "Session locked", nil
		},
	}
}

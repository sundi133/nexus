package command

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/votal-ai/nexus/agent/internal/updates"
)

// UpdatesAction installs OS updates from a signed command: {"scope": "security"|"all",
// "restart": "never"|"if_needed"}. A restart, when allowed and needed, goes through the same
// restart action admins use (with its warning to the signed-in person).
func UpdatesAction(restart Executor, recheck func()) ArgExecutor {
	return func(ctx context.Context, raw json.RawMessage) (string, json.RawMessage, error) {
		var a struct {
			Scope   string `json:"scope"`
			Restart string `json:"restart"`
		}
		_ = json.Unmarshal(raw, &a)
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
			return string(out), err
		}
		has := func(n string) bool { _, err := exec.LookPath(n); return err == nil }
		// Installs run in the check-in loop (like scripts): bound them so a stuck installer can't
		// keep the device silent for longer than an hour.
		ictx, cancel := context.WithTimeout(ctx, installTimeout)
		defer cancel()
		msg, err := updates.Install(ictx, runtime.GOOS, run, has, a.Scope != "all")
		if recheck != nil {
			recheck()
		}
		if err != nil {
			return "", nil, err
		}
		restarted := false
		if a.Restart == "if_needed" && needsRestart(msg) && restart != nil {
			if _, rerr := restart(ctx); rerr == nil {
				restarted = true
				msg += "; restarting"
			}
		}
		data, _ := json.Marshal(map[string]any{"summary": msg, "restarted": restarted})
		return msg, data, nil
	}
}

const installTimeout = time.Hour

func needsRestart(installMsg string) bool {
	switch runtime.GOOS {
	case "windows":
		return strings.Contains(installMsg, "reboot True")
	case "linux":
		_, err := os.Stat("/var/run/reboot-required")
		return err == nil
	case "darwin":
		return strings.Contains(strings.ToLower(installMsg), "restart")
	}
	return false
}

package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	scriptMaxBytes   = 256 << 10 // the script itself
	scriptMaxOutput  = 64 << 10  // what's reported back (the rest is dropped, and said so)
	scriptMaxTimeout = 30 * time.Minute
)

// ScriptArgs is what the organization signed: the script and how to run it.
type ScriptArgs struct {
	Shell   string `json:"shell"` // sh | bash | zsh | powershell
	Script  string `json:"script"`
	Timeout int    `json:"timeout_seconds"`
}

// capped keeps the first max bytes written to it.
type capped struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.truncated = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}

// interpreter returns the program and arguments that run a script file, on this OS.
func interpreter(goos, shell, path string) (string, []string, error) {
	switch shell {
	case "sh", "bash", "zsh":
		if goos == "windows" {
			return "", nil, fmt.Errorf("%s scripts don't run on Windows: use powershell", shell)
		}
		return "/bin/" + shell, []string{path}, nil
	case "powershell":
		if goos != "windows" {
			if p, err := exec.LookPath("pwsh"); err == nil {
				return p, []string{"-NoProfile", "-NonInteractive", "-File", path}, nil
			}
			return "", nil, errors.New("PowerShell isn't installed on this device")
		}
		return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path}, nil
	}
	return "", nil, fmt.Errorf("unknown shell %q", shell)
}

// ScriptAction runs an administrator's script from a signed command, as the agent's user (root
// or SYSTEM), with a time limit, and reports its exit code and (capped) output.
func ScriptAction(stateDir string) ArgExecutor {
	return func(ctx context.Context, raw json.RawMessage) (string, json.RawMessage, error) {
		var a ScriptArgs
		if json.Unmarshal(raw, &a) != nil || a.Script == "" {
			return "", nil, errors.New("the command has no script")
		}
		if len(a.Script) > scriptMaxBytes {
			return "", nil, errors.New("the script is too large")
		}
		timeout := time.Duration(a.Timeout) * time.Second
		if timeout <= 0 || timeout > scriptMaxTimeout {
			timeout = 5 * time.Minute
		}
		ext := map[string]string{"powershell": ".ps1"}[a.Shell]
		if ext == "" {
			ext = ".sh"
		}
		dir := filepath.Join(stateDir, "scripts")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", nil, err
		}
		f, err := os.CreateTemp(dir, "run-*"+ext)
		if err != nil {
			return "", nil, err
		}
		defer os.Remove(f.Name())
		if _, err := f.WriteString(a.Script); err != nil {
			f.Close()
			return "", nil, err
		}
		f.Close()
		prog, args, err := interpreter(runtime.GOOS, a.Shell, f.Name())
		if err != nil {
			return "", nil, err
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, prog, args...)
		cmd.Dir = dir
		setProcessGroup(cmd) // a timeout ends the whole tree, not just the shell
		out := &capped{max: scriptMaxOutput}
		cmd.Stdout, cmd.Stderr = out, out
		cmd.WaitDelay = 5 * time.Second
		started := time.Now()
		runErr := cmd.Run()
		elapsed := time.Since(started)
		exit := 0
		timedOut := ctx.Err() == context.DeadlineExceeded
		var ee *exec.ExitError
		switch {
		case timedOut:
			exit = -1
		case errors.As(runErr, &ee):
			exit = ee.ExitCode()
		case runErr != nil:
			return "", nil, runErr
		}
		data, _ := json.Marshal(map[string]any{"exit_code": exit, "output": out.buf.String(), "truncated": out.truncated, "timed_out": timedOut, "duration_ms": elapsed.Milliseconds()})
		msg := fmt.Sprintf("exit %d in %s", exit, elapsed.Round(100*time.Millisecond))
		if timedOut {
			msg = fmt.Sprintf("stopped after %s (time limit)", timeout)
		}
		if exit != 0 {
			return msg, data, fmt.Errorf("%s", msg)
		}
		return msg, data, nil
	}
}

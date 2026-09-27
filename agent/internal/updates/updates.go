package updates

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Run executes a command and returns its combined output (faked in tests).
type Run func(ctx context.Context, name string, args ...string) (string, error)

// Report is what the agent sends with its check-in.
type Report struct {
	CheckedAt string   `json:"checked_at"`
	Available []Update `json:"available"`
	Error     string   `json:"error,omitempty"`
}

const winCheck = `$s = New-Object -ComObject Microsoft.Update.Session; $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'"); ` +
	`@($r.Updates | ForEach-Object { [pscustomobject]@{ Title = $_.Title; Security = [bool]($_.Categories | Where-Object { $_.Name -match 'Security|Critical' }); Restart = [bool]($_.InstallationBehavior.RebootBehavior -ne 0); Upgrade = [bool]($_.Categories | Where-Object { $_.Name -eq 'Upgrades' }) } }) | ConvertTo-Json -Compress`

// winInstall installs what the check would find (security only, or everything but feature upgrades), and says whether a restart is needed.
const winInstall = `$s = New-Object -ComObject Microsoft.Update.Session; $r = $s.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'"); ` +
	`$c = New-Object -ComObject Microsoft.Update.UpdateColl; foreach ($u in $r.Updates) { if ($u.Categories | Where-Object { $_.Name -eq 'Upgrades' }) { continue }; if (-not $SECURITY_ONLY -or ($u.Categories | Where-Object { $_.Name -match 'Security|Critical' })) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$c.Add($u) } }; ` +
	`if ($c.Count -eq 0) { 'installed 0'; exit 0 }; $d = $s.CreateUpdateDownloader(); $d.Updates = $c; [void]$d.Download(); $i = $s.CreateUpdateInstaller(); $i.Updates = $c; $res = $i.Install(); ` +
	`"installed $($c.Count) result $($res.ResultCode) reboot $($res.RebootRequired)"`

// Check lists pending updates on this OS.
func Check(ctx context.Context, goos string, run Run, has func(string) bool) ([]Update, error) {
	switch goos {
	case "darwin":
		return macUpdates(ctx, run)
	case "windows":
		out, err := run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", winCheck)
		if err != nil {
			return nil, fmt.Errorf("Windows Update: %s", firstLine(out, err))
		}
		return ParseWindowsUpdates(out)
	case "linux":
		switch {
		case has("apt-get"):
			if out, err := run(ctx, "apt-get", "update", "-qq"); err != nil {
				return nil, fmt.Errorf("apt-get update: %s", firstLine(out, err))
			}
			out, err := run(ctx, "apt", "list", "--upgradable")
			if err != nil {
				return nil, fmt.Errorf("apt list: %s", firstLine(out, err))
			}
			return ParseAptUpgradable(out), nil
		case has("dnf"):
			sec, _ := run(ctx, "dnf", "-q", "updateinfo", "list", "--security")
			out, err := run(ctx, "dnf", "-q", "check-update")
			var ee *exec.ExitError
			if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 100) { // 100: updates available
				return nil, fmt.Errorf("dnf: %s", firstLine(out, err))
			}
			return ParseDnfCheckUpdate(out, ParseDnfSecurity(sec)), nil
		}
		return nil, errors.New("no apt or dnf on this device")
	}
	return nil, fmt.Errorf("%s isn't supported", goos)
}

// Install installs pending updates (security only, or all). Restarting is left to the caller.
func Install(ctx context.Context, goos string, run Run, has func(string) bool, securityOnly bool) (string, error) {
	switch goos {
	case "darwin":
		// By label, never --all or --recommended: those would start a major macOS upgrade too.
		// Every other macOS update counts as security, so both scopes install the same set.
		ups, err := macUpdates(ctx, run)
		if err != nil {
			return "", err
		}
		args := []string{"--install"}
		for _, u := range ups {
			if !u.Upgrade {
				args = append(args, u.Label)
			}
		}
		if len(args) == 1 {
			return "no updates to install", nil
		}
		out, err := run(ctx, "softwareupdate", append(args, "--agree-to-license")...)
		if err != nil {
			// Apple silicon needs an MDM bootstrap token (or the user) for macOS itself.
			return out, fmt.Errorf("softwareupdate: %s", firstLine(out, err))
		}
		return lastLine(out), nil
	case "windows":
		script := strings.Replace(winInstall, "$SECURITY_ONLY", map[bool]string{true: "$true", false: "$false"}[securityOnly], 1)
		out, err := run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
		if err != nil {
			return out, fmt.Errorf("Windows Update: %s", firstLine(out, err))
		}
		return lastLine(out), nil
	case "linux":
		switch {
		case has("apt-get"):
			if !securityOnly {
				out, err := run(ctx, "apt-get", "-y", "-q", "-o", "Dpkg::Options::=--force-confold", "upgrade")
				if err != nil {
					return out, fmt.Errorf("apt-get upgrade: %s", firstLine(out, err))
				}
				return lastLine(out), nil
			}
			list, err := run(ctx, "apt", "list", "--upgradable")
			if err != nil {
				return list, fmt.Errorf("apt list: %s", firstLine(list, err))
			}
			var names []string
			for _, u := range ParseAptUpgradable(list) {
				if u.Security {
					names = append(names, u.Name)
				}
			}
			if len(names) == 0 {
				return "no security updates", nil
			}
			out, err := run(ctx, "apt-get", append([]string{"-y", "-q", "-o", "Dpkg::Options::=--force-confold", "--only-upgrade", "install"}, names...)...)
			if err != nil {
				return out, fmt.Errorf("apt-get install: %s", firstLine(out, err))
			}
			return fmt.Sprintf("upgraded %d security packages", len(names)), nil
		case has("dnf"):
			args := []string{"-y", "-q", "upgrade"}
			if securityOnly {
				args = append(args, "--security")
			}
			out, err := run(ctx, "dnf", args...)
			if err != nil {
				return out, fmt.Errorf("dnf upgrade: %s", firstLine(out, err))
			}
			return lastLine(out), nil
		}
		return "", errors.New("no apt or dnf on this device")
	}
	return "", fmt.Errorf("%s isn't supported", goos)
}

func macUpdates(ctx context.Context, run Run) ([]Update, error) {
	ver, _ := run(ctx, "sw_vers", "-productVersion")
	out, err := run(ctx, "softwareupdate", "-l")
	if err != nil && !strings.Contains(out, "Software Update") {
		return nil, fmt.Errorf("softwareupdate: %s", firstLine(out, err))
	}
	return ParseSoftwareUpdate(out, major(ver)), nil
}

func firstLine(out string, err error) string {
	out = strings.TrimSpace(out)
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		out = out[:i]
	}
	if out == "" && err != nil {
		return err.Error()
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func lastLine(out string) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if len(l) > 200 {
		l = l[:200]
	}
	return l
}

// Checker checks in the background (at startup and every Every) and keeps the latest report.
type Checker struct {
	GOOS  string
	Run   Run
	Has   func(string) bool
	Every time.Duration

	mu     sync.Mutex
	report *Report
	busy   bool
	last   time.Time
}

// Report is the latest check, or nil before the first one finishes. It also starts one when due.
func (c *Checker) Report() *Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.busy && time.Since(c.last) >= c.Every {
		c.busy, c.last = true, time.Now()
		go c.check()
	}
	return c.report
}

// Recheck makes the next Report start a fresh check (after an install).
func (c *Checker) Recheck() {
	c.mu.Lock()
	c.last = time.Time{}
	c.mu.Unlock()
}

func (c *Checker) check() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	ups, err := Check(ctx, c.GOOS, c.Run, c.Has)
	r := &Report{CheckedAt: time.Now().UTC().Format(time.RFC3339), Available: ups}
	if r.Available == nil {
		r.Available = []Update{}
	}
	if err != nil {
		r.Error = err.Error()
	}
	c.mu.Lock()
	c.report, c.busy = r, false
	c.mu.Unlock()
}

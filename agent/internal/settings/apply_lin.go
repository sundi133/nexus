package settings

import (
	"strconv"
	"strings"

	"github.com/votal-ai/nexus/agent/internal/collect"
)

const (
	dconfProfile = "/etc/dconf/profile/user"
	dconfDB      = "/etc/dconf/db/local.d"
	dconfFile    = dconfDB + "/00-nexus-screen-lock"
	dconfLocks   = dconfDB + "/locks/nexus-screen-lock"
)

// Linux: ufw or firewalld; the GNOME screen lock through the system dconf database (locked, so
// people can't lengthen it); disk encryption (LUKS) is chosen at install time.
func applyLinux(sys Sys, d Desired) Outcome {
	var o Outcome
	if d.Firewall {
		o.Results = append(o.Results, linuxFirewall(sys))
	}
	if d.ScreenLockMinutes > 0 {
		o.Results = append(o.Results, linuxScreenLock(sys, d.ScreenLockMinutes))
	}
	if d.DiskEncryption { // escrow alone is a Windows (BitLocker) matter: nothing to report here
		o.Results = append(o.Results, Result{Key: "disk_encryption", Status: Unsupported, Detail: "LUKS encryption is set up when the OS is installed; re-provision this device with encryption"})
	}
	return o
}

func linuxFirewall(sys Sys) Result {
	switch {
	case sys.LookPath("ufw"):
		out, err := sys.Run("ufw", "status")
		if err == nil && collect.ParseUfw(out).Status == collect.On {
			return Result{Key: "firewall", Status: Compliant}
		}
		detail := "ufw turned on (incoming connections denied by default)"
		// Never lock out remote administration: allow SSH before denying incoming connections.
		if sys.LookPath("sshd") || sys.LookPath("/usr/sbin/sshd") {
			if _, err := sys.Run("ufw", "allow", "OpenSSH"); err != nil { // the app profile; plain port 22 if it's missing
				if out, err := sys.Run("ufw", "allow", "22/tcp"); err != nil {
					return failed("firewall", "couldn't allow SSH before turning ufw on; left it off", out, err)
				}
			}
			detail += "; SSH allowed"
		}
		if out, err := sys.Run("ufw", "--force", "enable"); err != nil {
			return failed("firewall", "couldn't turn ufw on", out, err)
		}
		return Result{Key: "firewall", Status: Applied, Detail: detail}
	case sys.LookPath("firewall-cmd"):
		if out, err := sys.Run("firewall-cmd", "--state"); err == nil && strings.TrimSpace(out) == "running" {
			return Result{Key: "firewall", Status: Compliant}
		}
		// firewalld's default zone keeps SSH open.
		if out, err := sys.Run("systemctl", "enable", "--now", "firewalld"); err != nil {
			return failed("firewall", "couldn't start firewalld", out, err)
		}
		return Result{Key: "firewall", Status: Applied, Detail: "firewalld started and enabled"}
	default:
		return Result{Key: "firewall", Status: Unsupported, Detail: "no ufw or firewalld on this device"}
	}
}

func linuxScreenLock(sys Sys, minutes int) Result {
	if !sys.LookPath("dconf") {
		return Result{Key: "screen_lock", Status: Unsupported, Detail: "no desktop settings database (dconf): nothing to lock on a server"}
	}
	settings := "# Managed by Votal Nexus: your organization's screen-lock policy\n" +
		"[org/gnome/desktop/session]\nidle-delay=uint32 " + strconv.Itoa(minutes*60) + "\n\n" +
		"[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 0\n"
	locks := "/org/gnome/desktop/session/idle-delay\n/org/gnome/desktop/screensaver/lock-enabled\n/org/gnome/desktop/screensaver/lock-delay\n"
	if cur, err := sys.ReadFile(dconfFile); err == nil && string(cur) == settings {
		if l, err := sys.ReadFile(dconfLocks); err == nil && string(l) == locks && profileHasLocal(sys) {
			return Result{Key: "screen_lock", Status: Compliant}
		}
	}
	// The user profile must read the system database; add it without replacing anything else.
	if !profileHasLocal(sys) {
		cur, _ := sys.ReadFile(dconfProfile)
		p := string(cur)
		if !strings.Contains(p, "user-db:") {
			p = "user-db:user\n" + p
		}
		p = strings.TrimRight(p, "\n") + "\nsystem-db:local\n"
		if err := writeAll(sys, "/etc/dconf/profile", dconfProfile, p); err != nil {
			return failed("screen_lock", "couldn't write the dconf profile", "", err)
		}
	}
	if err := writeAll(sys, dconfDB, dconfFile, settings); err != nil {
		return failed("screen_lock", "couldn't write the screen-lock settings", "", err)
	}
	if err := writeAll(sys, dconfDB+"/locks", dconfLocks, locks); err != nil {
		return failed("screen_lock", "couldn't lock the screen-lock settings", "", err)
	}
	if out, err := sys.Run("dconf", "update"); err != nil {
		return failed("screen_lock", "dconf update failed", out, err)
	}
	return Result{Key: "screen_lock", Status: PendingRestart, Detail: "GNOME locks after " + strconv.Itoa(minutes) + " min of inactivity; applies at the next sign-in"}
}

func profileHasLocal(sys Sys) bool {
	b, err := sys.ReadFile(dconfProfile)
	return err == nil && strings.Contains(string(b), "system-db:local")
}

func writeAll(sys Sys, dir, path, content string) error {
	if err := sys.MkdirAll(dir); err != nil {
		return err
	}
	return sys.WriteFile(path, []byte(content))
}

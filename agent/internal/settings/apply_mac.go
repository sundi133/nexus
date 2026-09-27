package settings

import (
	"strings"
)

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// macOS: the application firewall can be turned on by root. The screen lock and FileVault are
// managed only through configuration profiles (MDM) or by the signed-in user.
func applyDarwin(sys Sys, d Desired) Outcome {
	var o Outcome
	if d.Firewall {
		out, err := sys.Run(socketfilterfw, "--getglobalstate")
		switch {
		case err != nil:
			o.Results = append(o.Results, failed("firewall", "couldn't read the firewall state", out, err))
		case strings.Contains(out, "enabled") || strings.Contains(out, "State = 1") || strings.Contains(out, "State = 2"):
			o.Results = append(o.Results, Result{Key: "firewall", Status: Compliant})
		default:
			if out, err := sys.Run(socketfilterfw, "--setglobalstate", "on"); err != nil {
				o.Results = append(o.Results, failed("firewall", "couldn't turn the firewall on", out, err))
			} else {
				o.Results = append(o.Results, Result{Key: "firewall", Status: Applied, Detail: "application firewall turned on"})
			}
		}
	}
	if d.ScreenLockMinutes > 0 {
		o.Results = append(o.Results, Result{Key: "screen_lock", Status: Unsupported, Detail: "macOS sets the screen lock only through a configuration profile: deploy one from your MDM (screensaver idle time and askForPassword)"})
	}
	if d.DiskEncryption { // escrow alone is a Windows (BitLocker) matter: nothing to report here
		o.Results = append(o.Results, Result{Key: "disk_encryption", Status: Unsupported, Detail: "FileVault is turned on by the user or by your MDM's FileVault payload, which also escrows the recovery key"})
	}
	return o
}

package settings

import (
	"strconv"
	"strings"

	"github.com/votal-ai/nexus/agent/internal/collect"
)

const policiesSystem = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

// Windows: the firewall for every profile, the machine inactivity limit (the Group Policy
// "Interactive logon: Machine inactivity limit"), BitLocker on the system drive with a TPM,
// and escrow of its recovery passwords.
func applyWindows(sys Sys, d Desired) Outcome {
	var o Outcome
	if d.Firewall {
		out, err := sys.Run("netsh", "advfirewall", "show", "allprofiles", "state")
		if err != nil {
			o.Results = append(o.Results, failed("firewall", "couldn't read the firewall state", out, err))
		} else if collect.ParseNetshFirewall(out).Status == collect.On {
			o.Results = append(o.Results, Result{Key: "firewall", Status: Compliant})
		} else if out, err := sys.Run("netsh", "advfirewall", "set", "allprofiles", "state", "on"); err != nil {
			o.Results = append(o.Results, failed("firewall", "couldn't turn the firewall on", out, err))
		} else {
			o.Results = append(o.Results, Result{Key: "firewall", Status: Applied, Detail: "Windows Firewall turned on for all profiles"})
		}
	}
	if d.ScreenLockMinutes > 0 {
		want := d.ScreenLockMinutes * 60
		cur := -1
		if out, err := sys.Run("reg", "query", policiesSystem, "/v", "InactivityTimeoutSecs"); err == nil {
			if n, err := strconv.Atoi(collect.ParseRegQuery(out)["InactivityTimeoutSecs"]); err == nil {
				cur = n
			}
		}
		if cur > 0 && cur <= want {
			o.Results = append(o.Results, Result{Key: "screen_lock", Status: Compliant})
		} else if out, err := sys.Run("reg", "add", policiesSystem, "/v", "InactivityTimeoutSecs", "/t", "REG_DWORD", "/d", strconv.Itoa(want), "/f"); err != nil {
			o.Results = append(o.Results, failed("screen_lock", "couldn't set the inactivity limit", out, err))
		} else {
			o.Results = append(o.Results, Result{Key: "screen_lock", Status: PendingRestart, Detail: "machine inactivity limit set to " + strconv.Itoa(d.ScreenLockMinutes) + " min; applies after a restart"})
		}
	}
	if d.DiskEncryption || d.EscrowRecoveryKeys {
		r, keys := bitlocker(sys, d)
		o.Results = append(o.Results, r)
		o.RecoveryKeys = keys
	}
	return o
}

func bitlocker(sys Sys, d Desired) (Result, []RecoveryKey) {
	const vol = "C:"
	status, err := sys.Run("manage-bde", "-status", vol)
	if err != nil && status == "" {
		return failed("disk_encryption", "couldn't read BitLocker status (BitLocker may not be available on this edition)", status, err), nil
	}
	on := ParseBitLockerOn(status)
	getKeys := func() []RecoveryKey {
		out, _ := sys.Run("manage-bde", "-protectors", "-get", vol, "-Type", "RecoveryPassword")
		return ParseRecoveryPasswords(vol, out)
	}
	keys := getKeys()
	res := Result{Key: "disk_encryption", Status: Compliant}
	if !on && d.DiskEncryption {
		tpm, _ := sys.Run("powershell", "-NoProfile", "-NonInteractive", "-Command", "(Get-Tpm).TpmReady")
		if !ParseTPMReady(tpm) {
			return Result{Key: "disk_encryption", Status: Unsupported, Detail: "no ready TPM: turn BitLocker on by hand or through your MDM"}, nil
		}
		// A recovery password first, so the drive can always be recovered, then the TPM, then encrypt.
		if len(keys) == 0 {
			if out, err := sys.Run("manage-bde", "-protectors", "-add", vol, "-RecoveryPassword"); err != nil {
				return failed("disk_encryption", "couldn't add a recovery password", out, err), nil
			}
			keys = getKeys()
		}
		if out, err := sys.Run("manage-bde", "-protectors", "-add", vol, "-TPM"); err != nil && !strings.Contains(strings.ToLower(out), "already") {
			return failed("disk_encryption", "couldn't add the TPM protector", out, err), keysIf(d, keys)
		}
		if out, err := sys.Run("manage-bde", "-on", vol, "-UsedSpaceOnly", "-SkipHardwareTest"); err != nil {
			return failed("disk_encryption", "couldn't turn BitLocker on", out, err), keysIf(d, keys)
		}
		res = Result{Key: "disk_encryption", Status: Applied, Detail: "BitLocker turned on for " + vol + "; encryption continues in the background"}
	} else if !on {
		res = Result{Key: "disk_encryption", Status: Compliant, Detail: "BitLocker is off; turning it on isn't enabled in the policy"}
	}
	if on && d.EscrowRecoveryKeys && len(keys) == 0 {
		// Protected only by the TPM: add a recovery password, so the drive can be recovered.
		if out, err := sys.Run("manage-bde", "-protectors", "-add", vol, "-RecoveryPassword"); err != nil {
			return failed("disk_encryption", "couldn't add a recovery password to escrow", out, err), nil
		}
		keys = getKeys()
		res.Detail = "recovery password added for escrow"
	}
	return res, keysIf(d, keys)
}

func keysIf(d Desired, keys []RecoveryKey) []RecoveryKey {
	if !d.EscrowRecoveryKeys {
		return nil
	}
	return keys
}

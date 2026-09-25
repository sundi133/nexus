//go:build windows

package state

import "golang.org/x/sys/windows"

// secureDir limits the state folder to SYSTEM and Administrators, not
// inherited from ProgramData (where every local user can read by default),
// and pushes that down to what's already inside: the device key and any
// enroll.conf left by the installer.
func secureDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
